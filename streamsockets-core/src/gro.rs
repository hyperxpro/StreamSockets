//! UDP_GRO support for the epoll path on Linux.
//!
//! `UDP_GRO` (Generic Receive Offload for UDP, kernel ≥ 5.0) lets the kernel
//! coalesce multiple datagrams into a single recv. The application enables it
//! via `setsockopt(SOL_UDP, UDP_GRO, 1)` on the receive socket and reads the
//! per-segment size from the `UDP_GRO` cmsg attached to each `recvmsg(2)`.
//!
//! This module provides:
//!
//! - [`enable_udp_gro`]: setsockopt helper, returns `Ok(true)` when the kernel
//!   accepted the option, `Ok(false)` if it returned ENOPROTOOPT (kernel too
//!   old or built without UDP_GRO support), `Err(_)` for unexpected failures.
//! - [`recvmsg_gro`]: a single recvmsg call that fills a buffer and returns
//!   a [`GroRecv`] describing the wire length, truncation status and (optional)
//!   GRO segment size.
//!
//! On non-Linux targets these helpers are absent; callers fall back to single
//! datagram per recv.

#![cfg(target_os = "linux")]

use std::io;
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::sys::socket::{cmsg_space, recvmsg, ControlMessageOwned, MsgFlags};

/// Defensive lower-bound for the per-recv cmsg control buffer.
///
/// Sized for the worst plausible co-enabled cmsg set on a UDP recv socket:
/// `UDP_GRO` (i32) + `IP_TOS` (i32) + `IPV6_RECVTCLASS` (i32) +
/// `SO_TIMESTAMPNS` (timespec). Each addend includes the platform's
/// `CMSG_SPACE` alignment padding via `cmsg_space::<T>()`. We then clamp to
/// a 256-byte floor: kernels evolve, and a too-small buffer means MSG_CTRUNC
/// — which corrupts segmentation by dropping the GRO cmsg.
pub const CMSG_BUF_SIZE: usize = {
    let lower = cmsg_space::<i32>()
        + cmsg_space::<i32>()
        + cmsg_space::<i32>()
        + cmsg_space::<libc::timespec>();
    if lower > 256 {
        lower
    } else {
        256
    }
};

/// Enable `UDP_GRO` on `fd`. Returns `Ok(true)` on success, `Ok(false)` if the
/// kernel refused with `ENOPROTOOPT` (treat as "not supported, fall back"),
/// `Err(_)` for any other failure.
pub fn enable_udp_gro<F: AsRawFd>(fd: &F) -> io::Result<bool> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt with a 4-byte int payload is a well-defined libc call;
    // the fd outlives the call by virtue of the `&F` borrow.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let errno = io::Error::last_os_error();
    if errno.raw_os_error() == Some(libc::ENOPROTOOPT) {
        return Ok(false);
    }
    Err(errno)
}

/// Outcome of a single recvmsg.
#[derive(Debug, Clone, Copy)]
pub struct GroRecv {
    /// Bytes copied into the caller's buffer (≤ buf.len()).
    pub bytes_in_buf: usize,
    /// True iff the kernel reported `MSG_TRUNC` (the datagram was larger than
    /// the buffer and got chopped).
    pub truncated: bool,
    /// Real datagram length on the wire (always ≥ `bytes_in_buf`).
    pub wire_len: usize,
    /// `Some(n)` indicates UDP_GRO coalesced the recv into chunks of `n` bytes.
    pub seg_size: Option<u16>,
}

/// One non-blocking `recvmsg` call. The caller must have already established
/// that the socket is readable (e.g. via `tokio::net::UdpSocket::readable`).
///
/// Linux man recvmsg(2): when `MSG_TRUNC` is passed *as a request flag* on a
/// datagram socket, the kernel returns the real datagram length (not the
/// buffer-capped length). We use that to detect and surface truncation.
///
/// `cmsg_buf` is a caller-owned scratch Vec recycled across recvs. The
/// function clears it on entry; capacity is preserved. If capacity is below
/// [`CMSG_BUF_SIZE`] we top it up (one-shot reallocation; expected to be a
/// no-op once the caller pre-sizes it). MSG_CTRUNC after recvmsg surfaces as
/// an `Err`: silently parsing a truncated cmsg stream means missing the
/// `UDP_GRO` segment-size cmsg and chopping a coalesced batch into a single
/// frame.
pub fn recvmsg_gro(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    cmsg_buf: &mut Vec<u8>,
) -> io::Result<GroRecv> {
    // Capture the buffer length up-front: `IoSliceMut::new(buf)` borrows
    // `buf` for the duration of the recvmsg, so we can't reach in for `len()`
    // afterwards.
    let buf_len = buf.len();
    let mut iov = [IoSliceMut::new(buf)];
    cmsg_buf.clear();
    if cmsg_buf.capacity() < CMSG_BUF_SIZE {
        cmsg_buf.reserve(CMSG_BUF_SIZE - cmsg_buf.capacity());
    }
    // Snapshot for diagnostics — `cmsg_buf` is borrowed mutably by recvmsg
    // for the lifetime of `res`, so we must capture the values up front to
    // log them later.
    let cmsg_buf_capacity = cmsg_buf.capacity();
    let cmsg_buf_len = cmsg_buf.len();
    let res = recvmsg::<()>(
        fd.as_raw_fd(),
        &mut iov,
        Some(cmsg_buf),
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
    )
    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;

    // MSG_CTRUNC: kernel had more cmsg data than fit in cmsg_buf. Surface as
    // Err; the operator's pool sizing is wrong AND the GRO segment cmsg may
    // have been dropped, which would silently fragment a coalesced batch.
    if res.flags.contains(MsgFlags::MSG_CTRUNC) {
        tracing::warn!(
            cmsg_buf_capacity,
            cmsg_buf_len,
            wire_len = res.bytes,
            "recvmsg returned MSG_CTRUNC; cmsg buffer too small for kernel cmsg payload"
        );
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "recvmsg cmsg buffer truncated (MSG_CTRUNC)",
        ));
    }

    let wire_len = res.bytes;
    let bytes_in_buf = wire_len.min(buf_len);
    let truncated = res.flags.contains(MsgFlags::MSG_TRUNC) || wire_len > buf_len;
    let mut seg_size: Option<u16> = None;
    for cmsg in res
        .cmsgs()
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
    {
        if let ControlMessageOwned::UdpGroSegments(n) = cmsg {
            // nix exposes the value as i32; UDP_GRO segment size fits in u16
            // (max MTU). Clamp defensively.
            if n > 0 {
                seg_size = Some(u16::try_from(n).unwrap_or(u16::MAX));
            }
        }
    }
    Ok(GroRecv {
        bytes_in_buf,
        truncated,
        wire_len,
        seg_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn enable_gro_on_udp_socket() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        // Result depends on kernel: Ok(true) on ≥ 5.0, Ok(false) on older or
        // when UDP_GRO is built out. Either is acceptable; only an unexpected
        // errno is a failure.
        let r = enable_udp_gro(&s);
        assert!(r.is_ok(), "unexpected setsockopt error: {r:?}");
    }

    /// Round-trip a single datagram through recvmsg_gro; no truncation, no
    /// coalescing.
    #[test]
    fn recvmsg_gro_returns_none_segment_for_single_datagram() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let b = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let _ = enable_udp_gro(&a);
        a.connect(b.local_addr().expect("test")).expect("test");
        b.connect(a.local_addr().expect("test")).expect("test");
        b.send(b"ping").expect("test");
        a.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("test");
        let mut buf = [0u8; 1500];
        let mut cmsg = Vec::with_capacity(CMSG_BUF_SIZE);
        let r = recvmsg_gro(a.as_fd(), &mut buf, &mut cmsg).expect("test");
        assert_eq!(r.bytes_in_buf, 4);
        assert_eq!(r.wire_len, 4);
        assert!(!r.truncated);
        assert_eq!(&buf[..r.bytes_in_buf], b"ping");
        // For a single 4-byte datagram, GRO doesn't coalesce; segment cmsg may
        // be absent. (On some kernels GRO emits cmsg with seg_size == n;
        // both behaviors are spec-compliant.)
        assert!(matches!(r.seg_size, None | Some(4)));
    }

    /// Sending a datagram larger than the recv buffer is detected via MSG_TRUNC
    /// (truncated=true, wire_len > bytes_in_buf).
    #[test]
    fn recvmsg_gro_detects_truncation() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let b = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        a.connect(b.local_addr().expect("test")).expect("test");
        b.connect(a.local_addr().expect("test")).expect("test");
        a.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("test");
        // Send 2000 bytes; recv into 64-byte buffer to force truncation.
        let payload = vec![0xAB; 2000];
        b.send(&payload).expect("test");
        let mut tiny = [0u8; 64];
        let mut cmsg = Vec::with_capacity(CMSG_BUF_SIZE);
        let r = recvmsg_gro(a.as_fd(), &mut tiny, &mut cmsg).expect("test");
        assert!(r.truncated, "expected MSG_TRUNC");
        assert_eq!(r.bytes_in_buf, 64);
        assert_eq!(r.wire_len, 2000);
    }

    /// Setting SO_TIMESTAMPNS attaches a sizeable cmsg; the recvmsg_gro
    /// caller's CMSG_BUF_SIZE accommodates it without MSG_CTRUNC. This is the
    /// happy-path side of the MSG_CTRUNC contract: with the documented
    /// pre-size, MSG_CTRUNC must not appear.
    #[test]
    fn recvmsg_gro_no_ctrunc_with_timestamping_enabled() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let b = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let one: libc::c_int = 1;
        // SAFETY: standard setsockopt with c_int payload.
        let rc = unsafe {
            libc::setsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "SO_TIMESTAMPNS setsockopt failed");
        a.connect(b.local_addr().expect("test")).expect("test");
        b.connect(a.local_addr().expect("test")).expect("test");
        b.send(b"hello").expect("test");
        a.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("test");
        let mut buf = [0u8; 1500];
        let mut cmsg = Vec::with_capacity(CMSG_BUF_SIZE);
        let r = recvmsg_gro(a.as_fd(), &mut buf, &mut cmsg).expect("test");
        assert_eq!(r.bytes_in_buf, 5);
        assert_eq!(r.wire_len, 5);
    }

    /// A deliberately undersized cmsg buffer causes MSG_CTRUNC and the
    /// function returns Err. We bypass the public API's reserve floor by
    /// constructing a Vec whose capacity is *exactly* CMSG_BUF_SIZE and then
    /// piling on enough enabled cmsgs that the kernel exceeds it. We can't
    /// reliably do that from userspace alone, so instead we test the
    /// component the public API delegates to — call nix::recvmsg directly
    /// with a capacity-3 cmsg buffer and SO_TIMESTAMPNS enabled, then assert
    /// MSG_CTRUNC fires. This pins the kernel/nix interface our error
    /// surfacing relies on.
    #[test]
    fn nix_recvmsg_msg_ctrunc_fires_when_cmsg_buf_too_small() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let b = std::net::UdpSocket::bind("127.0.0.1:0").expect("test");
        let one: libc::c_int = 1;
        // SAFETY: standard setsockopt.
        let rc = unsafe {
            libc::setsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);
        a.connect(b.local_addr().expect("test")).expect("test");
        b.connect(a.local_addr().expect("test")).expect("test");
        b.send(b"hello").expect("test");
        a.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("test");
        let mut buf = [0u8; 1500];
        let mut iov = [IoSliceMut::new(&mut buf)];
        // Capacity 3: smaller than any single cmsg header, so the kernel
        // cannot fit the SO_TIMESTAMPNS cmsg → MSG_CTRUNC.
        let mut tiny: Vec<u8> = Vec::with_capacity(3);
        let res = recvmsg::<()>(
            a.as_fd().as_raw_fd(),
            &mut iov,
            Some(&mut tiny),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        )
        .expect("test");
        assert!(
            res.flags.contains(MsgFlags::MSG_CTRUNC),
            "kernel did not report MSG_CTRUNC with capacity-3 cmsg buf"
        );
    }
}
