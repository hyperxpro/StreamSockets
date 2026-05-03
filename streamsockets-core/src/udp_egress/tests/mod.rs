use super::*;
use std::sync::Arc;

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
