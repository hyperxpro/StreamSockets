//! Regression guard for FIX.md §3.2 / §10.1: a wire-level `Close(1002)`
//! from the peer MUST trigger a reconnect when `EXIT_ON_FAILURE=false`, not
//! leave the client permanently Idle/Terminated.
//!
//! The original symptom was: a proxy or intermediary closes the connection
//! with code 1002; the v2.0.0 client classified that as terminal and entered
//! `Idle-after-Terminated` for the rest of the process lifetime. Under
//! §10.1's always-reconnect contract the same close now flows through the
//! same code path as any other transient disconnect.
//!
//! Strategy: spin up a fake WS server that accepts the upgrade, waits long
//! enough for the client to send its queue-bootstrap frame, then sends
//! `Close(1002, "forced by test")`. Assert the server gets at least two
//! distinct TCP accepts (initial + reconnect) within the deadline.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fastwebsockets::{Frame, OpCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::test]
async fn close_1002_triggers_reconnect_not_terminate() {
    common::init_tracing_for_tests();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let connects = Arc::new(AtomicU32::new(0));
    let connects_for_server = connects.clone();

    let server_handle = tokio::spawn(async move {
        accept_loop_send_close(listener, connects_for_server, 1002, b"forced by test").await;
    });

    // Echo target for the upstream UDP socket.
    let (upstream_port, _echo) = common::spawn_udp_echo().await;
    let client_udp_port = common::free_udp_port().await;
    let mut cfg = common::default_client_cfg(port, client_udp_port, upstream_port);
    cfg.retry_initial_delay_ms = 50;
    cfg.retry_max_delay_ms = 200;
    cfg.retry_budget = 100; // generous so budget exhaustion never fires
    cfg.exit_on_failure = false;

    let (_client_handle, shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    // Fire one UDP packet so the FSM exits its Idle-on-first-packet wait and
    // dials. After Close(1002) the FSM should reconnect — driven by the
    // queued bootstrap packet that's still pending after the disconnect.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    // Keep sending periodically so the queue stays non-empty across reconnects.
    let probe_for_task = probe;
    let target_for_task = target;
    let pump = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = probe_for_task.send_to(b"hello", target_for_task).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    // Wait up to 5 s for ≥ 2 connects.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if connects.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let total = connects.load(Ordering::SeqCst);
    shutdown.cancel();
    pump.abort();
    server_handle.abort();

    assert!(
        total >= 2,
        "expected ≥2 connects after Close(1002); got {total}. \
         If only 1, the client treated 1002 as terminal (regression on FIX.md §10.1)."
    );
}

/// Per-connection handler: read one frame from the client (its bootstrap
/// binary frame), then send Close(code, reason). The client's auto_close
/// mirror is consumed implicitly when the connection is dropped.
async fn accept_loop_send_close(
    listener: TcpListener,
    connects: Arc<AtomicU32>,
    code: u16,
    reason: &'static [u8],
) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        connects.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = hyper::service::service_fn(move |mut req| async move {
                let upgrade = fastwebsockets::upgrade::upgrade(&mut req);
                match upgrade {
                    Ok((response, fut)) => {
                        tokio::spawn(async move {
                            if let Ok(mut ws) = fut.await {
                                // Read frames until we see either the
                                // bootstrap binary frame or a close handshake;
                                // bounded by 1 s so a misbehaving client
                                // doesn't hang the test.
                                let read =
                                    tokio::time::timeout(Duration::from_secs(1), ws.read_frame())
                                        .await;
                                // If the client already closed first, skip
                                // our forced-close — there's no socket left.
                                if let Ok(Ok(f)) = read {
                                    if matches!(f.opcode, OpCode::Close) {
                                        return;
                                    }
                                }
                                let _ = ws.write_frame(Frame::close(code, reason)).await;
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
