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

/// Verify that `localhost` resolves on hosts where IPv6 loopback is
/// available. Skips silently when the host kernel/userspace doesn't bind ::1
/// (some minimal CI containers, sandboxed runners) — the resolver itself is
/// covered by the v4 test above; this one specifically guards against an
/// IPv4-only resolver shortcut hiding a v6 regression.
///
/// `#[ignore]` because the test harness binds the server on 127.0.0.1 only;
/// dual-stack server bind requires test-side wiring that overlaps with the
/// server-fixer agent's in-flight CIDR / bind-address refactor. Run manually
/// with `cargo test -- --ignored route_localhost_v6_when_available` once
/// that work lands. The resolver-side coverage (does `localhost` ever
/// produce a v6 address?) is exercised by the upstream `hickory-resolver`
/// unit suite — this file's coverage gap is the end-to-end path.
#[tokio::test]
#[ignore]
async fn route_localhost_v6_when_available() {
    common::init_tracing_for_tests();

    // Probe: can we bind ::1? If not, skip the test (some containers).
    let v6_echo = match tokio::net::UdpSocket::bind("[::1]:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipping v6 localhost test — ::1 not bindable on this host: {e}");
            return;
        }
    };
    let echo_port = v6_echo.local_addr().unwrap().port();
    let echo_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = v6_echo.recv_from(&mut buf).await else {
                return;
            };
            let _ = v6_echo.send_to(&buf[..n], peer).await;
        }
    });

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let client_udp_port = common::free_udp_port().await;

    let yaml = format!(
        r#"
accounts:
  - name: alice
    token: 'tok'
    reuse: false
    routes:
      - 'localhost:{echo_port}'
      - '[::1]:{echo_port}'
    allowedIps:
      - '127.0.0.1'
      - '::1'
"#
    );
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    let mut cfg = common::default_client_cfg(server_port, client_udp_port, echo_port);
    cfg.auth_token = "tok".into();
    cfg.route = format!("localhost:{echo_port}");
    let _client = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(300)).await;

    let game = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let mut got = false;
    for _ in 0..15 {
        game.send_to(b"v6-hello", target).await.unwrap();
        let mut buf = [0u8; 64];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(500), game.recv_from(&mut buf)).await
        {
            if &buf[..n] == b"v6-hello" {
                got = true;
                break;
            }
        }
    }
    echo_handle.abort();
    assert!(
        got,
        "echo via localhost (with v6 upstream available) failed"
    );
}
