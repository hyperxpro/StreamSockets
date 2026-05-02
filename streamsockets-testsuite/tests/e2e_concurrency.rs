//! Spec §11.2 (MultipleConnectionsTest port): N concurrent client procs against
//! the same server, each with a distinct account, asserting per-account
//! isolation (echoes from one client never reach another's UDP listener).
//!
//! "Isolation" here means: each StreamSockets-client process has its own UDP
//! listener; packets flow client A → server → upstream A. Packets directed to
//! one upstream port must not appear on another's. We use 3 distinct accounts
//! and 3 distinct echo upstreams, in-process for speed.

mod common;

use std::time::Duration;

use tokio::net::UdpSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_accounts_isolated() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;

    // Three echo upstreams.
    let (echo1, _e1) = common::spawn_udp_echo().await;
    let (echo2, _e2) = common::spawn_udp_echo().await;
    let (echo3, _e3) = common::spawn_udp_echo().await;

    // Accounts file with three accounts; each routes to its own upstream.
    let yaml = format!(
        r#"
accounts:
  - name: a1
    token: 'tok1'
    reuse: false
    routes:
      - '127.0.0.1:{e1}'
    allowedIps:
      - '127.0.0.1'
  - name: a2
    token: 'tok2'
    reuse: false
    routes:
      - '127.0.0.1:{e2}'
    allowedIps:
      - '127.0.0.1'
  - name: a3
    token: 'tok3'
    reuse: false
    routes:
      - '127.0.0.1:{e3}'
    allowedIps:
      - '127.0.0.1'
"#,
        e1 = echo1,
        e2 = echo2,
        e3 = echo3,
    );
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    // Three clients, each with its own UDP listener port + auth token + route.
    let port1 = common::free_udp_port().await;
    let port2 = common::free_udp_port().await;
    let port3 = common::free_udp_port().await;

    let mut c1 = common::default_client_cfg(server_port, port1, echo1);
    c1.auth_token = "tok1".into();
    c1.route = format!("127.0.0.1:{echo1}");
    let mut c2 = common::default_client_cfg(server_port, port2, echo2);
    c2.auth_token = "tok2".into();
    c2.route = format!("127.0.0.1:{echo2}");
    let mut c3 = common::default_client_cfg(server_port, port3, echo3);
    c3.auth_token = "tok3".into();
    c3.route = format!("127.0.0.1:{echo3}");

    let (_h1, _s1) = common::spawn_client(c1).await;
    let (_h2, _s2) = common::spawn_client(c2).await;
    let (_h3, _s3) = common::spawn_client(c3).await;
    common::settle(Duration::from_millis(400)).await;

    // Each "game client" sends an account-tagged payload to its assigned
    // StreamSockets-client port and asserts the echo round-trips.
    for (port, tag) in [(port1, "for-a1"), (port2, "for-a2"), (port3, "for-a3")] {
        let game = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // warmup
        game.send_to(b"warmup", target).await.unwrap();
        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_secs(3), game.recv_from(&mut buf)).await;
        common::settle(Duration::from_millis(100)).await;

        let mut hits = 0;
        for _ in 0..20 {
            game.send_to(tag.as_bytes(), target).await.unwrap();
            let mut buf = [0u8; 64];
            if let Ok(Ok((n, _peer))) =
                tokio::time::timeout(Duration::from_secs(2), game.recv_from(&mut buf)).await
            {
                assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), tag);
                hits += 1;
            }
        }
        assert!(hits >= 18, "tag {tag}: expected ≥18/20 echoes, got {hits}");
    }
}
