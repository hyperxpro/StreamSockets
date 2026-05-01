//! Verify the authorization split: 401 (auth) / 403 (ip / route) / 409 (reuse).

mod common;

use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

async fn raw_handshake(
    server_port: u16,
    token: &str,
    route_address: &str,
    route_port: &str,
) -> u16 {
    let tcp = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let req = Request::builder()
        .uri("/tunnel")
        .header("Host", "127.0.0.1")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("X-Auth-Type", "Token")
        .header("X-Auth-Token", token)
        .header("X-Route-Address", route_address)
        .header("X-Route-Port", route_port)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    resp.status().as_u16()
}

#[tokio::test]
async fn route_denied_403() {
    common::init_tracing_for_tests();
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let yaml = common::default_accounts_yaml(8888);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(150)).await;

    let status = raw_handshake(server_port, "secret-token", "127.0.0.1", "9999").await;
    assert_eq!(status, 403, "route not in allowlist must be 403");
}

#[tokio::test]
async fn ip_denied_403() {
    common::init_tracing_for_tests();
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    // Restrict the only allowed IP to a non-loopback range.
    let yaml = r#"
accounts:
  - name: bob
    token: 'tok'
    reuse: true
    routes:
      - '127.0.0.1:8888'
    allowedIps:
      - '10.99.99.0/24'
"#
    .to_string();
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(150)).await;

    let status = raw_handshake(server_port, "tok", "127.0.0.1", "8888").await;
    assert_eq!(status, 403, "loopback IP outside allowlist must be 403");
}

#[tokio::test]
async fn reuse_conflict_409() {
    common::init_tracing_for_tests();
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;
    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(150)).await;

    // Spawn a long-lived client to grab the lease.
    let client_udp_port = common::free_udp_port().await;
    let cfg = common::default_client_cfg(server_port, client_udp_port, echo_port);
    let _client = common::spawn_client(cfg).await;

    // Send one UDP packet so the client transitions to Live and acquires the lease.
    let game = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let _ = game.send_to(b"prime", target).await;
    common::settle(Duration::from_millis(500)).await;

    // Second handshake with the same token should hit 409.
    let status = raw_handshake(
        server_port,
        "secret-token",
        "127.0.0.1",
        &echo_port.to_string(),
    )
    .await;
    assert_eq!(status, 409, "reuse=false with active lease must be 409");
}

#[tokio::test]
async fn happy_path_101() {
    common::init_tracing_for_tests();
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;
    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(150)).await;

    let status = raw_handshake(
        server_port,
        "secret-token",
        "127.0.0.1",
        &echo_port.to_string(),
    )
    .await;
    assert_eq!(status, 101, "valid handshake must switch protocols");
}
