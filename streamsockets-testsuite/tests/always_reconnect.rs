//! Regression guard for FIX.md §10.1 (always-reconnect contract). A fake WS
//! server closes the connection with each canonical RFC 6455 close code
//! plus a TCP-RST case. For `EXIT_ON_FAILURE=false` the client MUST
//! reconnect within the deadline; for `EXIT_ON_FAILURE=true` the client
//! worker MUST exit (its JoinHandle completes) within the deadline.
//!
//! Codes covered: {1000, 1001, 1002, 1003, 1008, 1011, 1012, TCP-RST}.
//! Notably {1002, 1003, 1008} used to be "terminal" → permanent Idle
//! under `EXIT_ON_FAILURE=false`. Under §10.1 they all reconnect.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fastwebsockets::{Frame, OpCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// What the fake server does after one inbound frame.
#[derive(Clone, Copy, Debug)]
enum Action {
    /// Send `Close(code, ...)` and let the close handshake complete.
    SendClose(u16),
    /// Drop the connection without a close — emulates TCP RST.
    TcpDrop,
}

#[tokio::test]
async fn always_reconnect_matrix_exit_on_failure_false() {
    common::init_tracing_for_tests();

    let actions: &[(&str, Action)] = &[
        ("Close(1000)", Action::SendClose(1000)),
        ("Close(1001)", Action::SendClose(1001)),
        ("Close(1002)", Action::SendClose(1002)),
        ("Close(1003)", Action::SendClose(1003)),
        ("Close(1008)", Action::SendClose(1008)),
        ("Close(1011)", Action::SendClose(1011)),
        ("Close(1012)", Action::SendClose(1012)),
        ("TCP-RST", Action::TcpDrop),
    ];

    for (name, action) in actions {
        let connects = run_one(*action, /* exit_on_failure */ false).await;
        assert!(
            connects >= 2,
            "{name}: expected ≥2 connects under EXIT_ON_FAILURE=false (always-reconnect); \
             got {connects}. Regression on FIX.md §10.1."
        );
    }
}

#[tokio::test]
async fn always_reconnect_matrix_exit_on_failure_true_exits_worker() {
    common::init_tracing_for_tests();

    // Under EXIT_ON_FAILURE=true, ANY disconnect signals exit. We pick a few
    // representative codes (terminal-class and transient-class) and assert
    // the worker exits cleanly. Full matrix would be redundant — the policy
    // branch is the same for every code.
    for (name, action) in [
        ("Close(1002)", Action::SendClose(1002)),
        ("Close(1011)", Action::SendClose(1011)),
        ("TCP-RST", Action::TcpDrop),
    ] {
        let exited = run_one_expect_exit(action).await;
        assert!(
            exited,
            "{name}: expected the worker to exit under EXIT_ON_FAILURE=true within deadline"
        );
    }
}

/// EXIT_ON_FAILURE=false path: spawn the fake server, count TCP accepts.
async fn run_one(action: Action, exit_on_failure: bool) -> u32 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connects = Arc::new(AtomicU32::new(0));
    let connects_for_server = connects.clone();

    let server_handle = tokio::spawn(async move {
        accept_loop(listener, connects_for_server, action).await;
    });

    let (upstream_port, _echo) = common::spawn_udp_echo().await;
    let client_udp_port = common::free_udp_port().await;
    let mut cfg = common::default_client_cfg(port, client_udp_port, upstream_port);
    cfg.retry_initial_delay_ms = 50;
    cfg.retry_max_delay_ms = 200;
    cfg.retry_budget = 100;
    cfg.exit_on_failure = exit_on_failure;

    let (_client_handle, shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    // Pump UDP so the queue never goes empty across reconnects.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let probe_for_task = probe;
    let target_for_task = target;
    let pump = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = probe_for_task.send_to(b"hello", target_for_task).await;
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
    shutdown.cancel();
    pump.abort();
    server_handle.abort();
    total
}

/// EXIT_ON_FAILURE=true path: assert the client worker's JoinHandle
/// completes (the FSM signals shutdown internally on the first disconnect).
async fn run_one_expect_exit(action: Action) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connects = Arc::new(AtomicU32::new(0));
    let connects_for_server = connects.clone();

    let server_handle = tokio::spawn(async move {
        accept_loop(listener, connects_for_server, action).await;
    });

    let (upstream_port, _echo) = common::spawn_udp_echo().await;
    let client_udp_port = common::free_udp_port().await;
    let mut cfg = common::default_client_cfg(port, client_udp_port, upstream_port);
    cfg.retry_initial_delay_ms = 50;
    cfg.retry_max_delay_ms = 200;
    cfg.retry_budget = 100;
    cfg.exit_on_failure = true;

    let (client_handle, _shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();
    let _ = probe.send_to(b"hello", target).await;

    // Worker should complete within 5 s after the first disconnect fires.
    let exited = tokio::time::timeout(Duration::from_secs(5), client_handle)
        .await
        .is_ok();

    server_handle.abort();
    exited
}

async fn accept_loop(listener: TcpListener, connects: Arc<AtomicU32>, action: Action) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        connects.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            match action {
                Action::SendClose(code) => {
                    let io = TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |mut req| async move {
                        let upgrade = fastwebsockets::upgrade::upgrade(&mut req);
                        match upgrade {
                            Ok((response, fut)) => {
                                tokio::spawn(async move {
                                    if let Ok(mut ws) = fut.await {
                                        let read = tokio::time::timeout(
                                            Duration::from_secs(1),
                                            ws.read_frame(),
                                        )
                                        .await;
                                        if let Ok(Ok(f)) = read {
                                            if matches!(f.opcode, OpCode::Close) {
                                                return;
                                            }
                                        }
                                        let _ = ws.write_frame(Frame::close(code, b"matrix")).await;
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
                }
                Action::TcpDrop => {
                    // Drop the TcpStream immediately after accept — no
                    // upgrade. The client's `dial` errors out with a
                    // transient transport error.
                    drop(stream);
                }
            }
        });
    }
}
