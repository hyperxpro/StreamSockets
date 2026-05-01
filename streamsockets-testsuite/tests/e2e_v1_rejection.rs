//! Verify that a v1-style handshake is rejected with HTTP 400.

mod common;

use std::time::Duration;

use http_body_util::{BodyExt, Empty};
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
    common::settle(Duration::from_millis(150)).await;

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
    // increments on this rejection. Scraped via the test server's metrics
    // listener (always-on in the test harness — `metrics_enabled: true`).
    let body = scrape_metrics(metrics_port).await;
    assert!(
        body.contains("streamsockets_handshake_failures_total"),
        "missing handshake_failures_total in /metrics output:\n{body}"
    );
    assert!(
        body.contains("reason=\"bad_request\""),
        "missing reason=bad_request label in /metrics output:\n{body}"
    );
    // Confirm the counter is at least 1 (renders as `... 1` or `... 1.0`-style;
    // prom-client text format omits trailing zeros).
    let saw_nonzero = body.lines().any(|l| {
        l.starts_with("streamsockets_handshake_failures_total")
            && l.contains("reason=\"bad_request\"")
            && l.split_whitespace()
                .last()
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|v| v >= 1.0)
    });
    assert!(saw_nonzero, "bad_request counter should be ≥1:\n{body}");
}

async fn scrape_metrics(port: u16) -> String {
    let url = format!("http://127.0.0.1:{port}/metrics");
    // Hand-roll a one-shot HTTP/1.1 GET — keeps the test free of reqwest.
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(&url)
        .header("Host", format!("127.0.0.1:{port}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap_or_default()
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
    common::settle(Duration::from_millis(150)).await;

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
    common::settle(Duration::from_millis(150)).await;

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

#[allow(dead_code)]
fn _force_link_bodyext() {
    // Ensure BodyExt's path is referenced if needed.
    let _ = http_body_util::Empty::<Bytes>::new().boxed();
}
