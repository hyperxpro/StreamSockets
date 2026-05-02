//! `UdpEgress` trait + `TokioUdp` impl per MIGRATION.md §4.
//!
//! The trait is the single platform abstraction over UDP. On Linux+iouring,
//! [`crate::uring_udp::IoUringUdp`] uses tokio-uring with kernel-registered
//! buffers (`IORING_REGISTER_BUFFERS`). On every other target — and on Linux
//! when `DISABLE_IOURING=true` or io_uring isn't supported — `TokioUdp`
//! delivers identical caller semantics on top of `tokio::net::UdpSocket`,
//! including `UDP_GRO` cmsg-driven segment splitting on Linux ≥ 5.0.
//!
//! The caller (server/client tunnel code) iterates `RecvBatch::segments` and
//! emits one WS binary frame per segment; the kernel decides segment count.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use smallvec::SmallVec;

use crate::buf_pool::{BufHandle, BufPool};

/// Up to 64 segments returned by a single recv. UDP_GRO can coalesce up to
/// ~43 MTU-sized datagrams into one 64 KiB recv (64 KiB / 1500); 64 leaves
/// headroom for jumbo / non-Ethernet links. `(u16, u16)` is exact — UDP
/// datagrams are bounded by the IP layer to 65535 bytes — saves 16 B per
/// slot vs `(usize, usize)` on 64-bit, keeping the inline footprint at
/// 256 B (0.0625 KiB) which fits in two cache lines.
pub type SegmentList = SmallVec<[(u16, u16); 64]>;

/// One UDP recv yielding zero or more datagrams.
///
/// `buf` owns the kernel-side buffer; `segments` enumerates `(offset, len)`
/// pairs into that buffer. With UDP_GRO disabled or unavailable, `segments`
/// always has length 1. With UDP_GRO active and the kernel coalescing,
/// `segments.len() > 1`.
pub struct RecvBatch {
    /// Backing buffer borrowed from the pool. Returns to the pool on drop.
    pub buf: BufHandle,
    /// `(offset, length)` pairs into [`Self::buf`], one per coalesced datagram.
    pub segments: SegmentList,
}

impl RecvBatch {
    /// Borrow segment `i` as a slice into `buf`.
    #[must_use]
    pub fn segment(&self, i: usize) -> &[u8] {
        let (off, len) = self.segments[i];
        let off = off as usize;
        let len = len as usize;
        &self.buf.as_ref()[off..off + len]
    }

    /// Total payload bytes across all segments.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|(_, l)| *l as usize).sum()
    }

    /// Number of segments in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Whether the batch carries no segments. Recv loops never observe this in
    /// practice (a successful recv yields at least one datagram), but guards
    /// callers against accidental zero-byte handling.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Asynchronous UDP egress trait — one impl per backend (tokio, tokio-uring).
///
/// Note: NOT `Send`. Per MIGRATION.md §4 ("Per-tunnel state pins to one
/// worker, so the WS task and the UDP task share a thread; cross-task
/// communication is `Rc<RefCell<...>>` or direct ownership (no `Send`
/// required).") The per-core current-thread runtime + SO_REUSEPORT model
/// keeps every tunnel local to one worker thread; `tokio_uring`'s `UdpSocket`
/// and `FixedBufRegistry` use `Rc<RefCell<...>>` internally so the trait is
/// thread-bound by construction.
#[async_trait(?Send)]
pub trait UdpEgress: 'static {
    /// Send one UDP datagram. The frame is the exact wire payload — no header
    /// or trailer is added.
    async fn send(&mut self, frame: Bytes) -> io::Result<()>;

    /// Receive one or more UDP datagrams into a buffer borrowed from `pool`.
    async fn recv_segments(&mut self, pool: &BufPool) -> io::Result<RecvBatch>;
}

/// Tokio (epoll) UDP backend. Used when io_uring is unavailable or disabled.
pub struct TokioUdp {
    socket: Arc<tokio::net::UdpSocket>,
    /// Whether `UDP_GRO` setsockopt has been accepted on this socket. Enables
    /// the cmsg-parsing recv path.
    gro_enabled: bool,
    /// Recycled cmsg control-buffer for both the GRO path and the non-GRO
    /// `recvmsg(MSG_TRUNC)` path on Linux. Pre-sized to
    /// [`crate::gro::CMSG_BUF_SIZE`] at construction so the hot path never
    /// allocates and never trips MSG_CTRUNC under the documented cmsg set.
    #[cfg(target_os = "linux")]
    cmsg_buf: Vec<u8>,
}

impl TokioUdp {
    /// Build from an already-bound `tokio::net::UdpSocket`. Caller is
    /// responsible for `connect()` + setsockopts (`SO_RCVBUF`,
    /// `IP_BIND_ADDRESS_NO_PORT`, etc.) per §7.1.
    #[must_use]
    pub fn from_socket(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            socket,
            gro_enabled: false,
            #[cfg(target_os = "linux")]
            cmsg_buf: Vec::with_capacity(crate::gro::CMSG_BUF_SIZE),
        }
    }

    /// Underlying socket — exposed for tunnel teardown ordering (UDP egress
    /// closed last per §6.7).
    #[must_use]
    pub fn socket(&self) -> &Arc<tokio::net::UdpSocket> {
        &self.socket
    }

    /// Enable `UDP_GRO` on the underlying socket. Returns `Ok(true)` if the
    /// kernel accepted the option, `Ok(false)` if the kernel reported
    /// `ENOPROTOOPT` (no UDP_GRO in this kernel — fall back silently),
    /// `Err(_)` on unexpected failure.
    ///
    /// On non-Linux targets this is a no-op returning `Ok(false)`.
    pub fn try_enable_gro(&mut self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            let ok = crate::gro::enable_udp_gro(&self.socket.as_fd())?;
            self.gro_enabled = ok;
            Ok(ok)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(false)
        }
    }

    /// Whether `UDP_GRO` is currently enabled on the socket.
    #[must_use]
    pub fn gro_enabled(&self) -> bool {
        self.gro_enabled
    }
}

#[async_trait(?Send)]
impl UdpEgress for TokioUdp {
    async fn send(&mut self, frame: Bytes) -> io::Result<()> {
        self.socket.send(&frame).await.map(|_| ())
    }

    async fn recv_segments(&mut self, pool: &BufPool) -> io::Result<RecvBatch> {
        let mut buf = pool.acquire();

        #[cfg(target_os = "linux")]
        if self.gro_enabled {
            use std::os::fd::AsFd;
            // Loop over readable() + non-blocking recvmsg until success.
            // recvmsg_gro passes MSG_DONTWAIT so it surfaces WouldBlock cleanly.
            loop {
                self.socket.readable().await?;
                match crate::gro::recvmsg_gro(self.socket.as_fd(), buf.as_mut(), &mut self.cmsg_buf)
                {
                    Ok(r) => {
                        if r.truncated {
                            // Surfacing Err is deliberate: silent truncation
                            // violates the tunnel's "no truncation" guarantee
                            // (spec §7.1). Callers map this to a counter +
                            // close 1009 ("Message Too Big").
                            let buf_len = buf.as_ref().len();
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                TruncatedRecv {
                                    wire_len: r.wire_len,
                                    buf_len,
                                },
                            ));
                        }
                        let n = r.bytes_in_buf;
                        let mut segments = SegmentList::new();
                        match r.seg_size {
                            Some(seg) if seg > 0 && (seg as usize) < n => {
                                // Coalesced. Split into seg_size chunks; last is tail.
                                let seg = seg as usize;
                                let mut off = 0;
                                while off < n {
                                    let take = (n - off).min(seg);
                                    segments.push((to_u16(off), to_u16(take)));
                                    off += take;
                                }
                            }
                            _ => {
                                segments.push((0, to_u16(n)));
                            }
                        }
                        return Ok(RecvBatch { buf, segments });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        // Non-GRO path. tokio::net::UdpSocket::recv calls plain recv(2) which
        // does NOT pass MSG_TRUNC, so >buf datagrams get silently chopped. We
        // cannot accept that — silent truncation corrupts WS frames downstream.
        // On Linux we go through nix recvmsg(MSG_TRUNC) to learn the wire size;
        // on non-Linux (dev-only) we fall back to tokio's recv (best effort).
        #[cfg(target_os = "linux")]
        {
            use std::io::IoSliceMut;
            use std::os::fd::AsFd;
            use std::os::fd::AsRawFd;
            loop {
                self.socket.readable().await?;
                let buf_len = buf.as_ref().len();
                self.cmsg_buf.clear();
                if self.cmsg_buf.capacity() < crate::gro::CMSG_BUF_SIZE {
                    let need = crate::gro::CMSG_BUF_SIZE - self.cmsg_buf.capacity();
                    self.cmsg_buf.reserve(need);
                }
                let mut iov = [IoSliceMut::new(buf.as_mut())];
                let res = nix::sys::socket::recvmsg::<()>(
                    self.socket.as_fd().as_raw_fd(),
                    &mut iov,
                    Some(&mut self.cmsg_buf),
                    nix::sys::socket::MsgFlags::MSG_DONTWAIT
                        | nix::sys::socket::MsgFlags::MSG_TRUNC,
                );
                match res {
                    Ok(msg) => {
                        let wire_len = msg.bytes;
                        if wire_len > buf_len {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                TruncatedRecv { wire_len, buf_len },
                            ));
                        }
                        let mut segments = SegmentList::new();
                        segments.push((0, to_u16(wire_len)));
                        return Ok(RecvBatch { buf, segments });
                    }
                    Err(nix::errno::Errno::EAGAIN) => continue,
                    Err(errno) => return Err(io::Error::from_raw_os_error(errno as i32)),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let n = self.socket.recv(buf.as_mut()).await?;
            let mut segments = SegmentList::new();
            segments.push((0, to_u16(n)));
            Ok(RecvBatch { buf, segments })
        }
    }
}

/// UDP datagrams cap at 65535 bytes; segment lengths fit in u16. Saturating
/// cast catches the impossible-but-defensive "wire_len > 65535" path.
#[inline]
fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Sidecar payload for the `io::Error` returned when the kernel reported
/// MSG_TRUNC (or the non-GRO recvmsg observed `wire_len > buf_len`). Callers
/// can downcast via [`classify_io_error`] for structured handling (close code
/// 1009, metric bump, etc).
#[derive(Debug)]
pub struct TruncatedRecv {
    /// Real datagram length on the wire (always > `buf_len`).
    pub wire_len: usize,
    /// Length of the recv buffer that the kernel chopped the datagram to.
    pub buf_len: usize,
}

impl std::fmt::Display for TruncatedRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "udp recv truncated: wire={} buf={}",
            self.wire_len, self.buf_len
        )
    }
}

impl std::error::Error for TruncatedRecv {}

/// Coarse classification of an `io::Error` returned by [`UdpEgress::recv_segments`].
/// Lets crates that don't depend on `streamsockets-core`'s private types check
/// for truncation without `Box<dyn Error>` downcasts at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// The recv saw a datagram larger than the buffer. Caller should bump a
    /// `udp_truncated_total` counter and (on the WS path) close with 1009.
    Truncated,
    /// Anything else.
    Other,
}

/// Classify an `io::Error` from a recv path. See [`ErrorClass`].
#[must_use]
pub fn classify_io_error(e: &io::Error) -> ErrorClass {
    if e.get_ref()
        .and_then(|inner| inner.downcast_ref::<TruncatedRecv>())
        .is_some()
    {
        ErrorClass::Truncated
    } else {
        ErrorClass::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cross test` runs aarch64 binaries under qemu-user, which mistranslates
    /// `recvmsg(MSG_TRUNC)` and SIGSEGVs the syscall translator. Tests that
    /// drive that surface bail out via `CROSS_RUNNER`; the same paths run
    /// natively on x86_64 in `build-test-linux`.
    fn skip_under_qemu_user(test_name: &str) -> bool {
        if std::env::var("CROSS_RUNNER").as_deref() == Ok("qemu-user") {
            eprintln!("skipping {test_name}: CROSS_RUNNER=qemu-user");
            return true;
        }
        false
    }

    #[tokio::test]
    async fn tokio_udp_round_trip() {
        if skip_under_qemu_user("tokio_udp_round_trip") {
            return;
        }
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("test");
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("test");
        a.connect(b.local_addr().expect("test"))
            .await
            .expect("test");
        b.connect(a.local_addr().expect("test"))
            .await
            .expect("test");

        let mut sender = TokioUdp::from_socket(Arc::new(a));
        let mut receiver = TokioUdp::from_socket(Arc::new(b));
        let pool = BufPool::new(4, 4096);

        sender
            .send(Bytes::from_static(b"ping"))
            .await
            .expect("test");
        let batch = receiver.recv_segments(&pool).await.expect("test");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.segment(0), b"ping");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tokio_udp_gro_enables_or_falls_back_cleanly() {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("test");
        let mut udp = TokioUdp::from_socket(Arc::new(a));
        // Result is Ok regardless: true on kernel ≥ 5.0, false on older.
        let r = udp.try_enable_gro();
        assert!(r.is_ok(), "unexpected GRO setsockopt error: {r:?}");
    }

    /// Non-GRO path: a datagram larger than the recv buffer returns Err with
    /// a TruncatedRecv payload, classified as ErrorClass::Truncated.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tokio_udp_non_gro_truncation_surfaces() {
        if skip_under_qemu_user("tokio_udp_non_gro_truncation_surfaces") {
            return;
        }
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("test");
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("test");
        a.connect(b.local_addr().expect("test"))
            .await
            .expect("test");
        b.connect(a.local_addr().expect("test"))
            .await
            .expect("test");

        let mut receiver = TokioUdp::from_socket(Arc::new(a));
        // Pool buffers are 64B; we send 2000B → wire_len > buf_len.
        let pool = BufPool::new(4, 64);
        b.send(&vec![0xAB; 2000]).await.expect("test");

        let err = match receiver.recv_segments(&pool).await {
            Ok(_) => panic!("expected truncation error"),
            Err(e) => e,
        };
        assert_eq!(classify_io_error(&err), ErrorClass::Truncated);
        let inner = err
            .get_ref()
            .and_then(|i| i.downcast_ref::<TruncatedRecv>())
            .expect("TruncatedRecv payload");
        assert_eq!(inner.wire_len, 2000);
        assert_eq!(inner.buf_len, 64);
    }

    #[test]
    fn classify_io_error_default_is_other() {
        let e = io::Error::from(io::ErrorKind::WouldBlock);
        assert_eq!(classify_io_error(&e), ErrorClass::Other);
    }
}
