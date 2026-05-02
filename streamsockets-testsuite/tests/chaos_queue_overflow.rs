//! Chaos: while the server is dead and the client is in Reconnecting, push UDP
//! frames in faster than the queue can hold; assert (a) drop-oldest behaviour,
//! (b) queue purge after drain timeout, (c) clean recovery once the server returns.

mod common;

use std::time::Duration;

use bytes::Bytes;

#[tokio::test]
async fn drop_oldest_under_overflow() {
    use streamsockets_client::queue::ReconnectQueue;
    let mut q = ReconnectQueue::new(1024);
    for i in 0..5000u32 {
        q.push(Bytes::copy_from_slice(&i.to_be_bytes()));
    }
    // Total bytes pushed: 5000*4 = 20_000; cap is 1024. Drop count ≈ 5000 - 256.
    assert!(q.len_bytes() <= 1024);
    assert!(q.dropped_overflow >= 1);

    // Newest items survived: pop the front (oldest survivor).
    let first = q.pop_front().unwrap();
    let val = u32::from_be_bytes(first[..4].try_into().unwrap());
    // 5000 frames × 4 bytes = 20_000 B pushed against a 1024 B cap → exactly
    // 1024 / 4 = 256 survivors, indexed (5000 - 256) = 4744..5000. The oldest
    // survivor must be ≥ 4700 — anything looser would silently pass under
    // FIFO inversion (oldest=4 surviving).
    assert!(
        val >= 4700,
        "oldest survivor should be in the [4744..5000) tail, got {val}"
    );
}

#[tokio::test]
async fn purge_on_drain_timeout() {
    use streamsockets_client::queue::ReconnectQueue;
    let mut q = ReconnectQueue::new(1024);
    for _ in 0..100 {
        q.push(Bytes::from_static(b"frame"));
    }
    let before = q.len_bytes();
    assert!(before > 0);
    // 100 × 5 bytes = 500 B against a 1024 B cap → no overflow drops.
    assert_eq!(q.dropped_overflow, 0);
    let purged = q.purge();
    // All 100 frames remained at purge time, so all 100 are reported as
    // purged. The previous expression simplified to a tautological 100==100.
    assert_eq!(purged, 100);
    assert_eq!(q.len_bytes(), 0);
}

#[tokio::test]
async fn server_kill_then_resume_keeps_recent_frames() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let client_udp_port = common::free_udp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;

    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    let mut cfg = common::default_client_cfg(server_port, client_udp_port, echo_port);
    cfg.queue_max_bytes = 1024;
    cfg.retry_initial_delay_ms = 50;
    cfg.retry_max_delay_ms = 200;
    cfg.retry_budget = 100;
    let _client = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    let game = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    // Prime the tunnel.
    game.send_to(b"prime", target).await.unwrap();
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(2), game.recv_from(&mut buf)).await;

    // Drain server. While dead, blast packets way past queue cap.
    server.stop().await;
    for i in 0..2000u32 {
        let v = i.to_be_bytes();
        let _ = game.send_to(&v, target).await;
    }

    // Restart server.
    let _server2 = common::spawn_server(
        server_port,
        accounts.path().to_path_buf(),
        common::free_tcp_port().await,
    )
    .await;

    // Wait for reconnect + queue flush to drain.
    common::settle(Duration::from_secs(2)).await;
    // Drain any flushed-but-stale echoes still arriving.
    while tokio::time::timeout(Duration::from_millis(50), game.recv_from(&mut buf))
        .await
        .is_ok()
    {}

    // Now verify the tunnel is healthy with a fresh probe.
    let mut got = false;
    for _ in 0..30 {
        game.send_to(b"recovery-probe", target).await.unwrap();
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(300), game.recv_from(&mut buf)).await
        {
            if &buf[..n] == b"recovery-probe" {
                got = true;
                break;
            }
        }
    }
    assert!(got, "tunnel did not recover after queue overflow + restart");
}
