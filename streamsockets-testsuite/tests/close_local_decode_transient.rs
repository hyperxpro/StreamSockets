//! Verifies FIX.md §3.1.2 + §10.1: a *locally* synthesized protocol error
//! (Path B — `WebSocketError::ReservedBitsNotZero`) results in a reconnect
//! under `EXIT_ON_FAILURE=false`, and the `protocol_violations_total`
//! counter is labeled with the exact variant (`reserved_bits_not_zero`),
//! NOT the historical catch-all `frame_format`.
//!
//! The fake server completes the WS upgrade via `fastwebsockets::upgrade`
//! and then extracts the raw underlying stream (via `WebSocket::into_inner`)
//! to write a deliberately malformed frame: `[0xC0, 0x00]` —
//! FIN=1, RSV1=1, opcode=0, mask=0, payload_len=0. fastwebsockets reads the
//! RSV bit, refuses to decode, and emits `Err(ReservedBitsNotZero)`. The
//! client's Path-B handler (fsm.rs) logs `source="local-decode"`,
//! `variant="reserved_bits_not_zero"`, increments the per-variant metric,
//! and — under always-reconnect — falls through to the reconnect loop.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn local_decode_error_triggers_reconnect_and_labels_variant() {
    common::init_tracing_for_tests();

    let metrics = streamsockets_metrics::Metrics::global();
    let before = metrics
        .protocol_violations
        .with_label_values(&["reserved_bits_not_zero"])
        .get();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connects = Arc::new(AtomicU32::new(0));
    let connects_for_server = connects.clone();

    let server_handle = tokio::spawn(async move {
        accept_send_rsv_bit_frame(listener, connects_for_server).await;
    });

    let (upstream_port, _echo) = common::spawn_udp_echo().await;
    let client_udp_port = common::free_udp_port().await;
    let mut cfg = common::default_client_cfg(port, client_udp_port, upstream_port);
    cfg.retry_initial_delay_ms = 50;
    cfg.retry_max_delay_ms = 200;
    cfg.retry_budget = 100;
    cfg.exit_on_failure = false;

    let (_client_handle, shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let pump = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = probe.send_to(b"hello", target).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if connects.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let total = connects.load(Ordering::SeqCst);
    let after = metrics
        .protocol_violations
        .with_label_values(&["reserved_bits_not_zero"])
        .get();

    shutdown.cancel();
    pump.abort();
    server_handle.abort();

    assert!(
        total >= 2,
        "expected ≥2 connects after locally-decoded protocol error; got {total}. \
         Regression on FIX.md §10.1 (Path B should reconnect under EXIT_ON_FAILURE=false)."
    );
    assert!(
        after - before >= 1.0,
        "expected protocol_violations{{reason=\"reserved_bits_not_zero\"}} to advance by ≥1; \
         before={before}, after={after}. Regression on FIX.md §3.1.2 \
         (per-variant labeling replacing the old 'frame_format' bucket)."
    );
}

/// Per-connection: upgrade WS, drain into raw stream, write `[0xC0, 0x00]`.
async fn accept_send_rsv_bit_frame(listener: TcpListener, connects: Arc<AtomicU32>) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        connects.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = hyper::service::service_fn(move |mut req| async move {
                match fastwebsockets::upgrade::upgrade(&mut req) {
                    Ok((response, fut)) => {
                        tokio::spawn(async move {
                            if let Ok(ws) = fut.await {
                                let mut raw = ws.into_inner();
                                // [FIN=1, RSV1=1 (illegal), opcode=0,
                                //  MASK=0, payload_len=0]. fastwebsockets'
                                // first-byte decoder trips ReservedBitsNotZero
                                // on the RSV1 bit.
                                let bad: [u8; 2] = [0xC0, 0x00];
                                let _ = raw.write_all(&bad).await;
                                let _ = raw.flush().await;
                                // Hold the socket briefly so the client has
                                // time to read before TCP teardown.
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                        });
                        Ok::<_, std::io::Error>(response)
                    }
                    Err(_) => Err(std::io::Error::other("upgrade failed")),
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });
    }
}
