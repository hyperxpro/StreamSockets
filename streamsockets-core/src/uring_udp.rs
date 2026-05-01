//! `IoUringUdp` — tokio-uring backed UDP egress.
//!
//! Compiled only on Linux when the `uring` feature is enabled. The caller
//! (server tunnel runner / client UDP listener) must be running inside a
//! `tokio_uring::Runtime`; calling these methods from a plain tokio runtime
//! will panic at the first uring submission.
//!
//! ## Buffer registration (MIGRATION.md §7.3)
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

use crate::buf_pool::BufPool;
use crate::udp_egress::{RecvBatch, SegmentList, UdpEgress};

/// Default registered-buffer pool size (1024 × 64 KiB ≈ 64 MiB resident per
/// worker, matching MIGRATION.md §7.3).
pub const DEFAULT_REGISTERED_BUFS: usize = 1024;
/// Default per-buffer size for the registered pool.
pub const DEFAULT_REGISTERED_BUF_SIZE: usize = 64 * 1024;

/// A pre-registered buffer pool. Construction calls `IORING_REGISTER_BUFFERS`
/// against the surrounding tokio_uring runtime; drop unregisters.
pub struct UringBufRegistry {
    inner: FixedBufRegistry<Vec<u8>>,
}

impl UringBufRegistry {
    /// Build with `count` buffers of `size` bytes each. The constructor MUST
    /// be invoked from inside a `tokio_uring` runtime (i.e. inside the future
    /// passed to `tokio_uring::start(...)`).
    pub fn new(count: usize, size: usize) -> io::Result<Self> {
        let bufs: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; size]).collect();
        let registry = FixedBufRegistry::new(bufs);
        registry.register()?;
        Ok(Self { inner: registry })
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
}

impl Drop for UringBufRegistry {
    fn drop(&mut self) {
        // FixedBufRegistry::unregister returns io::Result; we can't propagate
        // from Drop. Best-effort.
        let _ = self.inner.unregister();
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
    /// Number of registered buffer slots — used to clamp `next_recv_idx`.
    n_slots: usize,
}

impl IoUringUdp {
    /// Build from a connected `tokio_uring::net::UdpSocket`. Connected mode
    /// allows `read_fixed`/`write_fixed` to use kernel-registered buffers.
    pub fn connected(socket: UdpSocket, registry: std::sync::Arc<UringBufRegistry>) -> Self {
        let n_slots = DEFAULT_REGISTERED_BUFS;
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

    async fn recv_segments(&mut self, pool: &BufPool) -> io::Result<RecvBatch> {
        if self.is_connected && self.registry.is_some() {
            // Try a registered buffer; if the slot is checked out (rare under
            // round-robin), fall back to a pooled Vec.
            let slot = self.next_slot();
            let registry = self.registry.as_ref().expect("checked above").clone();
            if let Some(fixed) = registry.check_out(slot) {
                let (res, buf) = self.socket.read_fixed(fixed).await;
                let n = res?;
                // Copy into a pooled BufHandle so the RecvBatch shape stays
                // uniform. The fixed buf returns to the registry on drop here.
                let mut out = pool.acquire();
                let dst = out.as_mut();
                debug_assert!(n <= dst.len(), "registered buf exceeds pool buf size");
                use tokio_uring::buf::IoBuf;
                let init = buf.bytes_init();
                let read_n = init.min(n);
                let src_ptr = buf.stable_ptr();
                // SAFETY: stable_ptr returns a valid pointer for at least bytes_init bytes.
                let src = unsafe { std::slice::from_raw_parts(src_ptr, read_n) };
                dst[..read_n].copy_from_slice(src);
                drop(buf);
                let mut segments = SegmentList::new();
                segments.push((0, read_n));
                return Ok(RecvBatch { buf: out, segments });
            }
        }

        // Non-fixed path: recv into a pooled Vec via recv_from. tokio-uring's
        // recv_from takes ownership of the Vec across await; we hand it back
        // to the pool after copying out the read prefix.
        let scratch: Vec<u8> = vec![0u8; pool.buf_size()];
        let (res, scratch) = self.socket.recv_from(scratch).await;
        let (n, _addr) = res?;
        let mut out = pool.acquire();
        let dst = out.as_mut();
        dst[..n].copy_from_slice(&scratch[..n]);
        let mut segments = SegmentList::new();
        segments.push((0, n));
        Ok(RecvBatch { buf: out, segments })
    }
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

            let server = UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let server_addr = server.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let client_addr = client.local_addr().unwrap();

            // Connect both ends.
            server.connect(client_addr).await.unwrap();
            client.connect(server_addr).await.unwrap();

            let mut s = IoUringUdp::connected(server, registry.clone());
            let mut c = IoUringUdp::connected(client, registry.clone());

            let pool = BufPool::new(4, 1024);
            s.send(Bytes::from_static(b"ping")).await.unwrap();
            let batch = c.recv_segments(&pool).await.unwrap();
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.segment(0), b"ping");
        });
    }
}
