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
//!   `(total_bytes, gro_segment_size)` — `gro_segment_size = None` means GRO
//!   was not engaged (i.e. one datagram).
//!
//! On non-Linux targets these helpers are absent; callers fall back to single
//! datagram per recv.

#![cfg(target_os = "linux")]

use std::io;
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};

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

/// One blocking `recvmsg` call. The caller must have already established that
/// the socket is readable (e.g. via `tokio::net::UdpSocket::async_io` returning
/// `Ready { is_readable: true, .. }`).
///
/// Returns `(bytes_read, segment_size)` where `segment_size = Some(n)` indicates
/// `UDP_GRO` coalesced the recv into chunks of `n` bytes (the trailing segment
/// may be shorter; standard UDP_GRO semantics).
pub fn recvmsg_gro(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, Option<u16>)> {
    let mut iov = [IoSliceMut::new(buf)];
    // CMSG buffer: one ControlMessage of size = sizeof(int). Be generous: 64
    // bytes covers UDP_GRO + a couple of extras (IP_PKTINFO, IP_RECVERR) without
    // hurting anything.
    let mut cmsg_buf: Vec<u8> = Vec::with_capacity(64);
    let res = recvmsg::<()>(
        fd.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;

    let bytes_read = res.bytes;
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
    Ok((bytes_read, seg_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn enable_gro_on_udp_socket() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // Result depends on kernel: Ok(true) on ≥ 5.0, Ok(false) on older or
        // when UDP_GRO is built out. Either is acceptable; only an unexpected
        // errno is a failure.
        let r = enable_udp_gro(&s);
        assert!(r.is_ok(), "unexpected setsockopt error: {r:?}");
    }

    /// Two-byte recv via GRO-supporting recvmsg. We just verify the wrapper
    /// round-trips a normal datagram (no GRO engaged → seg_size = None).
    #[test]
    fn recvmsg_gro_returns_none_segment_for_single_datagram() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = enable_udp_gro(&a);
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        b.send(b"ping").unwrap();
        a.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut buf = [0u8; 1500];
        let (n, seg) = recvmsg_gro(a.as_fd(), &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"ping");
        // For a single 4-byte datagram, GRO doesn't coalesce; segment cmsg may
        // be absent. (On some kernels GRO emits cmsg with seg_size == n;
        // both behaviors are spec-compliant.)
        assert!(matches!(seg, None | Some(4)));
    }
}
