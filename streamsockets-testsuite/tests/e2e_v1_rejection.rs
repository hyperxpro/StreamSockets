//! Verify that a v1-style handshake is rejected with HTTP 400.
//!
//! Counter assertions use the snapshot-then-delta pattern (see
//! `tests/common/mod.rs` — "Counter isolation strategy") because
//! `Metrics::global()` is a process-global registry shared across tests in
//! the same binary.

mod common;

use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

#[tokio::test]
async fn v1_handshake_rejected_400() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let yaml = common::default_accounts_yaml(8888);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::wait_for_metrics_ready(metrics_port, Duration::from_secs(5))
        .await
        .expect("metrics ready");

    // Snapshot the counter BEFORE driving the rejection — counter bleed across
    // tests in the same binary makes absolute >= 1 fail spuriously.
    let before = common::parse_counter_sample(
        &common::scrape_metrics(metrics_port).await,
        "streamsockets_handshake_failures_total",
        &[r#"reason="bad_request""#],
    );

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

    // v1-only headers — no X-Route-Address / X-Route-Port — must yield 400.
    let req = Request::builder()
        .uri("/tunnel")
        .header("Host", "127.0.0.1")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("X-Auth-Type", "Token")
        .header("X-Auth-Token", "secret-token")
        .header("X-Auth-Route", "127.0.0.1:8888")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 400, "v1 handshake should be 400");

    // Spec §11.2 + VERDICT advisory: assert the
    // `streamsockets_handshake_failures_total{reason="bad_request"}` counter
    // increments by ≥1 on this rejection. Snapshot-delta — see module doc.
    let after = match common::wait_for_metric_at_least(
        metrics_port,
        "streamsockets_handshake_failures_total",
        &[r#"reason="bad_request""#],
        before + 1.0,
        Duration::from_secs(3),
    )
    .await
    {
        Ok(v) => v,
        Err(last) => {
            let body = common::scrape_metrics(metrics_port).await;
            panic!(
                "bad_request counter did not increase: before={before}, last={last}, body=\n{body}"
            );
        }
    };
    assert!(
        after >= before + 1.0,
        "bad_request counter delta < 1: before={before}, after={after}"
    );
}

#[tokio::test]
async fn missing_token_rejected_400() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let yaml = common::default_accounts_yaml(8888);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

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
        .header("X-Route-Address", "127.0.0.1")
        .header("X-Route-Port", "8888")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn auth_fail_returns_401() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let yaml = common::default_accounts_yaml(8888);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

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
        .header("X-Auth-Token", "wrong-token")
        .header("X-Route-Address", "127.0.0.1")
        .header("X-Route-Port", "8888")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}
