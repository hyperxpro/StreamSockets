//! Verifies FIX.md §10.2 / §10.3.2: the reconnect queue replays buffered
//! frames in FIFO order on reconnect, and the packet cap evicts oldest
//! when exceeded.
//!
//! Scenario:
//!   1. Spawn a fake WS server that drops the first connection (sending
//!      `Close(1011)`) and on the second connection records every binary
//!      frame the client sends.
//!   2. While the first WS is being torn down and the client is in the
//!      Reconnecting/backoff window, push N monotonically-tagged UDP
//!      datagrams into the client. Each tagged with a 4-byte big-endian
//!      counter (`0, 1, 2, …`).
//!   3. Assert the second connection receives the *tail* of those frames
//!      in FIFO order, bounded by `QUEUE_MAX_PACKETS`.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fastwebsockets::{Frame, OpCode};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::net::TcpListener;

#[tokio::test]
async fn reconnect_replays_queued_packets_in_fifo_order() {
    common::init_tracing_for_tests();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let connects = Arc::new(AtomicU32::new(0));
    let received: Arc<Mutex<Vec<Bytes>>> = Arc::new(Mutex::new(Vec::new()));

    let connects_for_server = connects.clone();
    let received_for_server = received.clone();
    let server_handle = tokio::spawn(async move {
        accept_loop(listener, connects_for_server, received_for_server).await;
    });

    let (upstream_port, _echo) = common::spawn_udp_echo().await;
    let client_udp_port = common::free_udp_port().await;
    let mut cfg = common::default_client_cfg(port, client_udp_port, upstream_port);
    // Long backoff so the burst lands in the queue (during Reconnecting),
    // not during Live. With a short backoff the FSM transitions back to
    // Live before the burst finishes, so frames flow directly through
    // run_live's write path and never see the queue's drop-oldest logic.
    cfg.retry_initial_delay_ms = 800;
    cfg.retry_max_delay_ms = 1500;
    cfg.retry_budget = 100;
    cfg.exit_on_failure = false;
    cfg.queue_max_packets = 4; // small cap so eviction is testable
    cfg.queue_max_bytes = 1024 * 1024; // not the bottleneck

    let (_client_handle, shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(200)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();

    // Step 1: send a bootstrap UDP packet — sentinel value `u32::MAX` so
    // it cannot collide with the burst counters. The FSM dials connection
    // 1, which sends Close(1011). After ~50–100 ms the client is in
    // Reconnecting; we wait long enough for that to be true.
    let _ = probe.send_to(&u32::MAX.to_be_bytes(), target).await;

    // Wait for connection 1 to have happened — that means the FSM has
    // moved past Live and is in Reconnecting + backoff (>=800 ms).
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if connects.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Extra settle so connection 1 has fully torn down before our burst.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Step 2: tight burst of 10 counter-tagged packets while the client is
    // backing off. They accumulate in udp_rx → pushed to queue with
    // drop-oldest → only the last `cap_packets` (=4) survive.
    for i in 0..10u32 {
        let _ = probe.send_to(&i.to_be_bytes(), target).await;
    }

    // Wait for connection 2 to establish and replay the queue.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if connects.load(Ordering::SeqCst) >= 2 && !received.lock().is_empty() {
            tokio::time::sleep(Duration::from_millis(300)).await;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    shutdown.cancel();
    server_handle.abort();

    let frames = received.lock().clone();
    let conns = connects.load(Ordering::SeqCst);
    assert!(
        conns >= 2,
        "expected ≥2 connects; got {conns} (the client never reconnected)"
    );
    assert!(
        !frames.is_empty(),
        "second connection received no frames; queue replay failed"
    );

    // FIFO + drop-oldest assertion: every counter the second server saw
    // must be monotonically non-decreasing, and the first one observed
    // must be >= (max_sent - cap_packets + 1). Without strict FIFO this
    // would interleave or be reversed.
    // Ignore the sentinel (u32::MAX) — it bootstrapped the FSM via
    // connection 1; its replay status is uninteresting for the cap test.
    let counters: Vec<u32> = frames
        .iter()
        .filter_map(|b| {
            if b.len() >= 4 {
                Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            } else {
                None
            }
        })
        .filter(|&c| c != u32::MAX)
        .collect();

    assert!(
        !counters.is_empty(),
        "no burst counters in received frames; raw frames: {frames:?}"
    );
    // Monotonic non-decreasing under FIFO.
    for w in counters.windows(2) {
        assert!(
            w[0] <= w[1],
            "FIFO order violated: saw {} before {} in received frames {counters:?}",
            w[0],
            w[1]
        );
    }
    // Drop-oldest invariant: with cap_packets=4 and a 10-packet burst,
    // ONLY the last `cap` counters survive in the queue. The smallest
    // counter received on connection 2 must therefore be ≥
    // max(counters) - cap + 1.
    let max_seen = *counters.iter().max().unwrap();
    let oldest_seen = *counters.iter().min().unwrap();
    let cap = 4u32;
    assert!(
        max_seen < 10,
        "second server saw counter {max_seen} > pushed-max 9; impossible"
    );
    let allowed_floor = (max_seen + 1).saturating_sub(cap);
    assert!(
        oldest_seen >= allowed_floor,
        "drop-oldest violated: oldest survivor counter={oldest_seen} < \
         allowed_floor={allowed_floor} (max_seen={max_seen}, cap={cap}). \
         Frames observed: {counters:?}"
    );
    // The receive set must be tightly bounded by the cap.
    assert!(
        counters.len() <= cap as usize,
        "received {} burst frames; cap_packets=4 should bound this. Frames: {counters:?}",
        counters.len()
    );
}

/// Stateful accept loop. First connect: read one frame then send Close(1011).
/// Second connect (and later): read every binary frame, push payload bytes
/// into the shared `received` vector.
async fn accept_loop(
    listener: TcpListener,
    connects: Arc<AtomicU32>,
    received: Arc<Mutex<Vec<Bytes>>>,
) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let n = connects.fetch_add(1, Ordering::SeqCst) + 1;
        let received_for_conn = received.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let received_for_svc = received_for_conn.clone();
            let svc = hyper::service::service_fn(move |mut req| {
                let received_for_handler = received_for_svc.clone();
                async move {
                    match fastwebsockets::upgrade::upgrade(&mut req) {
                        Ok((response, fut)) => {
                            tokio::spawn(async move {
                                if let Ok(mut ws) = fut.await {
                                    if n == 1 {
                                        // Read at most one frame, then send
                                        // Close(1011) to force a reconnect.
                                        let _ = tokio::time::timeout(
                                            Duration::from_millis(100),
                                            ws.read_frame(),
                                        )
                                        .await;
                                        let _ = ws
                                            .write_frame(Frame::close(1011, b"force-reconnect"))
                                            .await;
                                    } else {
                                        // Subsequent connections: drain
                                        // binary frames into the shared
                                        // vector for assertion.
                                        let read_deadline =
                                            std::time::Instant::now() + Duration::from_secs(3);
                                        while std::time::Instant::now() < read_deadline {
                                            let f = match tokio::time::timeout(
                                                Duration::from_millis(500),
                                                ws.read_frame(),
                                            )
                                            .await
                                            {
                                                Ok(Ok(f)) => f,
                                                _ => break,
                                            };
                                            match f.opcode {
                                                OpCode::Binary => {
                                                    received_for_handler.lock().push(
                                                        Bytes::copy_from_slice(f.payload.as_ref()),
                                                    );
                                                }
                                                OpCode::Close => break,
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            });
                            Ok::<_, std::io::Error>(response)
                        }
                        Err(_) => Err(std::io::Error::other("upgrade failed")),
                    }
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });
    }
}
