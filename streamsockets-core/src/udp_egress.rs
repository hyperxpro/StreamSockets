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

/// Up to 16 segments returned by a single recv. Real GRO fan-out is typically
/// well below this; the SmallVec keeps the steady-state allocation count at
/// zero.
pub type SegmentList = SmallVec<[(usize, usize); 16]>;

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
        &self.buf.as_ref()[off..off + len]
    }

    /// Total payload bytes across all segments.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|(_, l)| *l).sum()
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
                match crate::gro::recvmsg_gro(self.socket.as_fd(), buf.as_mut()) {
                    Ok((n, seg_size)) => {
                        let mut segments = SegmentList::new();
                        match seg_size {
                            Some(seg) if seg > 0 && (seg as usize) < n => {
                                // Coalesced. Split into seg_size chunks; last is tail.
                                let seg = seg as usize;
                                let mut off = 0;
                                while off < n {
                                    let take = (n - off).min(seg);
                                    segments.push((off, take));
                                    off += take;
                                }
                            }
                            _ => {
                                segments.push((0, n));
                            }
                        }
                        return Ok(RecvBatch { buf, segments });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        let n = self.socket.recv(buf.as_mut()).await?;
        let mut segments = SegmentList::new();
        segments.push((0, n));
        Ok(RecvBatch { buf, segments })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokio_udp_round_trip() {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();

        let mut sender = TokioUdp::from_socket(Arc::new(a));
        let mut receiver = TokioUdp::from_socket(Arc::new(b));
        let pool = BufPool::new(4, 4096);

        sender.send(Bytes::from_static(b"ping")).await.unwrap();
        let batch = receiver.recv_segments(&pool).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.segment(0), b"ping");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tokio_udp_gro_enables_or_falls_back_cleanly() {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut udp = TokioUdp::from_socket(Arc::new(a));
        // Result is Ok regardless: true on kernel ≥ 5.0, false on older.
        let r = udp.try_enable_gro();
        assert!(r.is_ok(), "unexpected GRO setsockopt error: {r:?}");
    }
}
