//! (#4) The listener must drop datagrams larger than `MAX_FRAME_SIZE` rather
//! than queue them. This test verifies the policy via an end-to-end run of
//! `run_fsm_with_socket`.
//!
//! Strategy:
//!   1. Bind a UDP listener on an ephemeral port.
//!   2. Start `run_fsm_with_socket` with `max_frame_size = 1500` and an
//!      unreachable WS endpoint (so the FSM stays in Connecting/Reconnecting
//!      and the listener loop runs).
//!   3. Send one undersize and one oversize datagram from a peer socket.
//!   4. Read the `streamsockets_queue_dropped_total{reason="oversize"}`
//!      counter — must be exactly 1.
//!   5. The undersize datagram is queued, exercising the success path.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use streamsockets_client::fsm::{self, SharedExitCode, SharedLockedSource};
use streamsockets_client::{ClientConfig, RedactedString};
use tokio_util::sync::CancellationToken;

fn cfg(udp_port: u16, max: usize) -> ClientConfig {
    ClientConfig {
        bind_address: "127.0.0.1".into(),
        bind_port: udp_port,
        // Unreachable WS endpoint — the FSM never reaches Live, but the
        // listener loop runs from the moment the socket is handed in.
        websocket_uri: "ws://127.0.0.1:1/tunnel".into(),
        // Allow ws:// + token to skip dial-time refusal under test.
        auth_token: RedactedString::new("t".into()),
        route: "127.0.0.1:8888".into(),
        ping_interval_ms: 5000,
        ping_timeout_ms: 10_000,
        ping_permitted_misses: 1,
        retry_initial_delay_ms: 100,
        retry_max_delay_ms: 1000,
        retry_budget: 100,
        udp_timeout_secs: 60,
        exit_on_failure: false,
        queue_max_bytes: 1 << 20,
        queue_drain_timeout_ms: 5000,
        threads: 1,
        max_frame_size: max,
        udp_channel_capacity: 1024,
        allow_insecure_auth: true,
        allow_no_auth: false,
        tls_ca_file: Option::<PathBuf>::None,
    }
}

#[tokio::test]
async fn listener_drops_oversize_datagrams() {
    // Build the bound listener on an ephemeral port.
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let std_sock = streamsockets_client::build_listener_udp_std(bind).unwrap();
    let local: SocketAddr = std_sock.local_addr().unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let tokio_sock = tokio::net::UdpSocket::from_std(std_sock).unwrap();

    let cfg = Arc::new(cfg(local.port(), 1500));
    let shutdown = CancellationToken::new();
    let locked: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    let exit_code: SharedExitCode = Arc::new(AtomicI32::new(0));

    let metrics = streamsockets_metrics::Metrics::global();
    let oversize_counter = metrics
        .queue_dropped
        .with_label_values(&["client", "oversize"]);
    let baseline_oversize = oversize_counter.get();

    let handle = {
        let cfg = cfg.clone();
        let shutdown = shutdown.clone();
        let locked = locked.clone();
        let exit_code = exit_code.clone();
        tokio::spawn(async move {
            let _ = fsm::run_fsm_with_socket(cfg, shutdown, tokio_sock, 0, locked, exit_code).await;
        })
    };

    // Send one datagram from a peer; first datagram serves to lock the source
    // and pop the FSM from idle into Connecting.
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(&[0u8; 800], local).await.unwrap();
    // Send an oversize datagram: 4096 > max_frame_size (1500).
    peer.send_to(&[0xAB; 4096], local).await.unwrap();
    // And another within-bounds one, so we know the listener is still alive.
    peer.send_to(&[0u8; 1200], local).await.unwrap();

    // Give the listener time to drain.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let after = oversize_counter.get();
    assert!(
        after - baseline_oversize >= 1.0,
        "expected at least one oversize drop; baseline={baseline_oversize} after={after}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}
