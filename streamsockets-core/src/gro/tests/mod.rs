use super::*;
use std::os::fd::{AsFd, AsRawFd};

/// `cross test` runs aarch64 binaries under qemu-user, which mistranslates
/// `recvmsg(MSG_TRUNC)` + ancillary cmsg payloads (assertions misfire and
/// the syscall translator occasionally SIGSEGVs). cross sets
/// `CROSS_RUNNER=qemu-user` on the container; tests that depend on the
/// kernel's actual behaviour for this surface bail out here. The same
/// paths are exercised natively by the x86_64 `build-test-linux` job.
fn skip_under_qemu_user(test_name: &str) -> bool {
    if std::env::var("CROSS_RUNNER").as_deref() == Ok("qemu-user") {
        eprintln!("skipping {test_name}: CROSS_RUNNER=qemu-user");
        return true;
    }
    false
}

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
    if skip_under_qemu_user("recvmsg_gro_no_ctrunc_with_timestamping_enabled") {
        return;
    }
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
    if skip_under_qemu_user("nix_recvmsg_msg_ctrunc_fires_when_cmsg_buf_too_small") {
        return;
    }
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
        MsgFlags::empty(),
    );
    let r = res.expect("recvmsg");
    assert!(r.cmsgs().is_err() || r.flags.contains(MsgFlags::MSG_CTRUNC));
}
