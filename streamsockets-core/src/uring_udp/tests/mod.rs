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
