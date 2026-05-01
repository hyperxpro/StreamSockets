//! Verify the upstream resolver handles `localhost` (string hostnames) end-to-end.

mod common;

use std::time::Duration;

use tokio::net::UdpSocket;

#[tokio::test]
async fn route_localhost_resolves() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let client_udp_port = common::free_udp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;

    let yaml = format!(
        r#"
accounts:
  - name: alice
    token: 'tok'
    reuse: false
    routes:
      - 'localhost:{}'
    allowedIps:
      - '127.0.0.1'
      - '::1'
"#,
        echo_port
    );
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(150)).await;

    let mut cfg = common::default_client_cfg(server_port, client_udp_port, echo_port);
    cfg.auth_token = "tok".into();
    cfg.route = format!("localhost:{}", echo_port);
    let _client = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(300)).await;

    let game = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let mut got = false;
    for _ in 0..15 {
        game.send_to(b"hello", target).await.unwrap();
        let mut buf = [0u8; 64];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(500), game.recv_from(&mut buf)).await
        {
            if &buf[..n] == b"hello" {
                got = true;
                break;
            }
        }
    }
    assert!(got, "echo via localhost route failed");
}
