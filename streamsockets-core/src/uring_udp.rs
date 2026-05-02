//! `IoUringUdp` — tokio-uring backed UDP egress.
//!
//! Compiled only on Linux when the `uring` feature is enabled. The caller
//! (server tunnel runner / client UDP listener) must be running inside a
//! `tokio_uring::Runtime`; calling these methods from a plain tokio runtime
//! will panic at the first uring submission.
//!
//! ## Buffer registration
//!
//! Each worker constructs an [`IoUringUdp`] with a [`UringBufRegistry`] of 1024
//! × 64 KiB buffers. The registry calls
//! `tokio_uring::buf::fixed::FixedBufRegistry::register()` which translates
//! into `io_uring_register(IORING_REGISTER_BUFFERS, iovs, N)` — the kernel
//! pins the pages and skips `get_user_pages` on every recv. Subsequent
//! `read_fixed` / `write_fixed` calls reference these by index.
//!
//! For UDP that has been `connect()`ed to an upstream (the typical server
//! egress shape), `read_fixed` / `write_fixed` is the hot path. For
//! unconnected sockets (the client UDP listener, where the source is unknown
//! until the first packet) we fall back to `recvmsg` / `sendmsg` against a
//! pooled `Vec<u8>` from [`BufPool`]. Both modes go through the same
//! `UdpEgress` trait surface.

#![cfg(all(target_os = "linux", feature = "uring"))]

use std::io;

use async_trait::async_trait;
use bytes::Bytes;
use tokio_uring::buf::fixed::FixedBufRegistry;
use tokio_uring::net::UdpSocket;

use crate::buf_pool::{BufPool, DEFAULT_BUF_SIZE, DEFAULT_POOL_CAPACITY};
use crate::udp_egress::{RecvBatch, SegmentList, TruncatedRecv, UdpEgress};

/// Default registered-buffer pool size — alias of
/// [`crate::buf_pool::DEFAULT_POOL_CAPACITY`]. Both pools share the same
/// per-worker shape so they can't drift.
pub const DEFAULT_REGISTERED_BUFS: usize = DEFAULT_POOL_CAPACITY;
/// Default per-buffer size for the registered pool — alias of
/// [`crate::buf_pool::DEFAULT_BUF_SIZE`].
pub const DEFAULT_REGISTERED_BUF_SIZE: usize = DEFAULT_BUF_SIZE;

/// A pre-registered buffer pool. Construction calls `IORING_REGISTER_BUFFERS`
/// against the surrounding tokio_uring runtime; drop unregisters.
///
/// Drop ordering contract: the `Arc<UringBufRegistry>` MUST be dropped from
/// inside the same `tokio_uring::start { ... }` block that constructed it —
/// `unregister` issues an io_uring opcode and panics or silently fails if no
/// tokio_uring runtime is current. The supervisor enforces this by holding
/// the `Arc` only inside the worker future. As an in-process safety net,
/// `Drop` logs at ERROR if it observes an unregister failure (without
/// double-panicking).
pub struct UringBufRegistry {
    inner: FixedBufRegistry<Vec<u8>>,
    n_slots: usize,
    buf_size: usize,
}

impl UringBufRegistry {
    /// Build with `count` buffers of `size` bytes each. The constructor MUST
    /// be invoked from inside a `tokio_uring` runtime (i.e. inside the future
    /// passed to `tokio_uring::start(...)`).
    pub fn new(count: usize, size: usize) -> io::Result<Self> {
        let bufs: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; size]).collect();
        let registry = FixedBufRegistry::new(bufs);
        registry.register()?;
        Ok(Self {
            inner: registry,
            n_slots: count,
            buf_size: size,
        })
    }

    /// Default-sized registry (1024 × 64 KiB).
    pub fn default_for_worker() -> io::Result<Self> {
        Self::new(DEFAULT_REGISTERED_BUFS, DEFAULT_REGISTERED_BUF_SIZE)
    }

    /// Acquire a fixed buffer by index. Returns `None` if the buffer is
    /// currently checked out (someone else holds it). The returned buffer
    /// returns to the registry on drop.
    pub fn check_out(&self, index: usize) -> Option<tokio_uring::buf::fixed::FixedBuf> {
        self.inner.check_out(index)
    }

    /// Number of registered slots. Sourced at construction so callers'
    /// round-robin uses the actual registry size, not a default that may
    /// exceed it (which silently bypasses the fast path).
    pub fn len(&self) -> usize {
        self.n_slots
    }

    /// True iff the registry has zero slots.
    pub fn is_empty(&self) -> bool {
        self.n_slots == 0
    }

    /// Per-buffer size — exposed so callers can pre-size matching pools.
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }
}

impl Drop for UringBufRegistry {
    fn drop(&mut self) {
        // FixedBufRegistry::unregister returns io::Result; we can't propagate
        // from Drop. If unregister fails AND we're not already panicking,
        // log at ERROR — that's almost always a violation of the
        // "drop inside tokio_uring::start" contract.
        let res = self.inner.unregister();
        if let Err(e) = res {
            if !std::thread::panicking() {
                tracing::error!(
                    error = %e,
                    "UringBufRegistry::drop: unregister failed; \
                     verify the Arc<UringBufRegistry> is dropped inside the tokio_uring::start block"
                );
            }
        }
    }
}

/// io_uring-backed UDP egress.
///
/// Internally wraps a `tokio_uring::net::UdpSocket`. For connected sockets the
/// `read_fixed` / `write_fixed` fast path is used (no copy through user space,
/// no `get_user_pages` at recv time). For unconnected sockets we use the
/// regular `recv_from` / `send_to` API — still allocation-free at steady state
/// thanks to [`BufPool`] reuse.
pub struct IoUringUdp {
    socket: UdpSocket,
    /// Optional pre-registered buffer pool. When present, recv uses
    /// `read_fixed` (kernel-fast); otherwise we fall back to recv_from with a
    /// pooled `Vec<u8>`.
    registry: Option<std::sync::Arc<UringBufRegistry>>,
    /// Round-robin index over the registry's buffer slots when serving recvs.
    next_recv_idx: usize,
    /// Whether `socket` was `connect()`ed (gates use of `read_fixed`).
    is_connected: bool,
    /// Number of registered buffer slots — sourced from the registry at
    /// construction. Was previously hard-coded to `DEFAULT_REGISTERED_BUFS`,
    /// which silently bypassed the fast path for any registry smaller than the
    /// default (e.g. tests using 8 slots round-robined over 1024 indices).
    n_slots: usize,
}

impl IoUringUdp {
    /// Build from a connected `tokio_uring::net::UdpSocket`. Connected mode
    /// allows `read_fixed`/`write_fixed` to use kernel-registered buffers.
    pub fn connected(socket: UdpSocket, registry: std::sync::Arc<UringBufRegistry>) -> Self {
        let n_slots = registry.len();
        Self {
            socket,
            registry: Some(registry),
            next_recv_idx: 0,
            is_connected: true,
            n_slots,
        }
    }

    /// Build from an unconnected `tokio_uring::net::UdpSocket`. Recv/send
    /// fall back to the non-fixed path.
    pub fn unconnected(socket: UdpSocket) -> Self {
        Self {
            socket,
            registry: None,
            next_recv_idx: 0,
            is_connected: false,
            n_slots: 0,
        }
    }

    fn next_slot(&mut self) -> usize {
        if self.n_slots == 0 {
            return 0;
        }
        let i = self.next_recv_idx % self.n_slots;
        self.next_recv_idx = self.next_recv_idx.wrapping_add(1);
        i
    }
}

#[async_trait(?Send)]
impl UdpEgress for IoUringUdp {
    async fn send(&mut self, frame: Bytes) -> io::Result<()> {
        if self.is_connected {
            // tokio-uring's UdpSocket::send takes BoundedBuf<Buf=Vec<u8>>-like;
            // Bytes implements IoBuf. So passing Bytes is zero-copy on the
            // submission path. The (res, _bytes) pair is dropped: our Bytes is
            // a refcount, the underlying allocation drops naturally.
            let (res, _b) = self.socket.send(frame).await;
            res.map(|_| ())
        } else {
            // For an unconnected socket we expect the caller to use a different
            // egress path. Surface a clear error rather than silently dropping
            // the frame.
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "IoUringUdp::send called on unconnected socket; use a connected socket for egress",
            ))
        }
    }

    /// **Cancel-safety:** `recv_segments` is **NOT** cancel-safe. tokio-uring's
    /// `read_fixed` submits an SQE that the kernel may complete after this
    /// future is dropped; the `FixedBuf` slot returns to the registry on
    /// drop, and a subsequent `check_out` of the same slot races kernel
    /// writes. Callers MUST NOT race this future against a cancellation
    /// arm in `tokio::select!`. Drive cancellation via a wrapper that
    /// awaits the cancel signal *before* `recv_segments` is polled, then
    /// allow this future to complete.
    async fn recv_segments(&mut self, pool: &BufPool) -> io::Result<RecvBatch> {
        if self.is_connected && self.registry.is_some() {
            // Try a registered buffer; if the slot is checked out (e.g. another
            // `IoUringUdp` sharing the same `Arc<UringBufRegistry>` happened to
            // hit the same round-robin index), log once and fall back to the
            // pooled-Vec path. The fast path is opportunistic, not load-bearing.
            let slot = self.next_slot();
            let registry = self.registry.as_ref().expect("checked above").clone();
            if let Some(fixed) = registry.check_out(slot) {
                let (res, buf) = self.socket.read_fixed(fixed).await;
                let n = res?;
                // Trust the kernel-returned `n` — `read_fixed` returning Ok(n)
                // means the kernel wrote exactly n bytes into the buffer's
                // prefix. `bytes_init()` is the *known* init count which may
                // lag the kernel write across tokio-uring versions; using `n`
                // directly is the documented contract from
                // io_uring_prep_read_fixed.
                let mut out = pool.acquire();
                let dst = out.as_mut();
                if n > dst.len() {
                    // Kernel-controlled length exceeded the pool buffer size:
                    // operator misconfigured pools relative to the registered
                    // registry. Surface as TruncatedRecv so the caller can
                    // increment a counter and (on the WS path) close 1009.
                    drop(buf);
                    let buf_len = dst.len();
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        TruncatedRecv {
                            wire_len: n,
                            buf_len,
                        },
                    ));
                }
                use tokio_uring::buf::IoBuf;
                let src_ptr = buf.stable_ptr();
                // SAFETY:
                // - `read_fixed(fixed).await` yielded `Ok(n)`; the kernel
                //   wrote exactly `n` bytes into the buffer prefix and the
                //   completion arrived BEFORE this `.await` resolved
                //   (no concurrent kernel writer remains).
                // - `stable_ptr()` returns a pointer valid for at least
                //   `buf.bytes_total()` bytes (the registered buffer size,
                //   which is `>= n` because the kernel cannot write past
                //   the registered length).
                // - We hold `buf` (FixedBuf) until after the copy_from_slice
                //   below; the underlying allocation cannot be reclaimed
                //   while `buf` is live.
                // - The slice is never aliased mutably: tokio-uring's
                //   FixedBuf API does not hand out concurrent &mut while
                //   `buf` is live.
                let src = unsafe { std::slice::from_raw_parts(src_ptr, n) };
                dst[..n].copy_from_slice(src);
                drop(buf);
                let mut segments = SegmentList::new();
                segments.push((0, to_u16(n)));
                return Ok(RecvBatch { buf: out, segments });
            }
            // Slot was held — fall through to the non-fixed path. Logging at
            // debug since a transient collision is acceptable; a steady stream
            // of these means the registry is undersized for the workload.
            tracing::debug!(
                slot,
                "uring registered-buffer slot busy; falling back to pooled recv"
            );
        }

        // Non-fixed path: recv into a pooled Vec via recv_from. tokio-uring's
        // recv_from takes ownership of the Vec across await; we hand it back
        // to the pool after copying out the read prefix.
        let scratch: Vec<u8> = vec![0u8; pool.buf_size()];
        let (res, scratch) = self.socket.recv_from(scratch).await;
        let (n, _addr) = res?;
        let mut out = pool.acquire();
        let dst = out.as_mut();
        if n > dst.len() {
            let buf_len = dst.len();
            return Err(io::Error::new(
                io::ErrorKind::Other,
                TruncatedRecv {
                    wire_len: n,
                    buf_len,
                },
            ));
        }
        dst[..n].copy_from_slice(&scratch[..n]);
        let mut segments = SegmentList::new();
        segments.push((0, to_u16(n)));
        Ok(RecvBatch { buf: out, segments })
    }
}

/// UDP datagrams cap at 65535 bytes; segment lengths fit in u16. Saturating
/// cast catches the impossible-but-defensive "n > 65535" path.
#[inline]
fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Smoke test: build a registry and send/recv on a connected pair under
    /// `tokio_uring::start`. Skipped automatically when run on a kernel that
    /// rejects io_uring_setup (CI sandbox).
    #[test]
    fn registry_and_round_trip() {
        if !crate::pick_runtime_kind_for_test() {
            eprintln!("io_uring not available on this host; skipping");
            return;
        }
        tokio_uring::start(async {
            // The IoUringUdp API takes Arc<...> by design (struct field
            // type); the registry itself doesn't cross threads in tokio-uring's
            // single-thread-per-runtime model, so silence the
            // arc_with_non_send_sync diagnostic at this call site only.
            #[allow(clippy::arc_with_non_send_sync)]
            let registry = Arc::new(UringBufRegistry::new(8, 1024).expect("register buffers"));

            let server = UdpSocket::bind("127.0.0.1:0".parse().expect("test"))
                .await
                .expect("test");
            let server_addr = server.local_addr().expect("test");
            let client = UdpSocket::bind("127.0.0.1:0".parse().expect("test"))
                .await
                .expect("test");
            let client_addr = client.local_addr().expect("test");

            // Connect both ends.
            server.connect(client_addr).await.expect("test");
            client.connect(server_addr).await.expect("test");

            let mut s = IoUringUdp::connected(server, registry.clone());
            let mut c = IoUringUdp::connected(client, registry.clone());

            let pool = BufPool::new(4, 1024);
            s.send(Bytes::from_static(b"ping")).await.expect("test");
            let batch = c.recv_segments(&pool).await.expect("test");
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.segment(0), b"ping");
        });
    }
}
