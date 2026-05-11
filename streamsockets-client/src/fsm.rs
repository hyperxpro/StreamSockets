//! Reconnect FSM: Idle → Connecting → Authenticating → Live ⇄ Reconnecting.
//!
//! Policy (§10.1 always-reconnect contract):
//!   - `EXIT_ON_FAILURE=true`  → log cause, stamp process exit 1, return.
//!   - `EXIT_ON_FAILURE=false` → log cause, reconnect after backoff (bounded
//!     only by `RETRY_BUDGET`). There is no per-close-code terminal branch:
//!     1002/1003/1008/1011/local decode errors/TCP RST all flow through the
//!     same reconnect loop. The diagnostic upgrade in §3.1 preserves the
//!     ability to localize the cause (Path A wire-close vs Path B locally
//!     synthesized) via log fields and per-variant metric labels.
//!
//! Single-source lock-on (§6.4): on the first UDP packet, lock `(src_ip, src_port)`
//! for the lifetime of the process. Subsequent packets from a foreign source are
//! dropped + counted in `streamsockets_client_foreign_sources_total`.
//!
//! Cancellation (§6.6): a per-process parent `CancellationToken` is passed in by
//! `lib::run()`. Each Connecting/Authenticating/Live cycle takes a fresh child
//! via `parent.child_token()`. SIGTERM/SIGINT cancels the parent → all children
//! → all `select!` arms wake → graceful WS Close 1001 + drain.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, WebSocketError};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backoff::Backoff;
use crate::queue::ReconnectQueue;
use crate::ws::{self};
use crate::ClientConfig;

/// Process-shared lock-on cell. `Arc<ArcSwapOption<SocketAddr>>` rather than
/// per-worker `Mutex<Option<SocketAddr>>`: with N workers all binding the same
/// UDP port via SO_REUSEPORT, each worker's listener was previously locking
/// its own source independently. The first datagram on each fanout-bucket
/// "won" — meaning N distinct sources could all forward to the relay
/// simultaneously, defeating the §6.4 single-source invariant. Process-shared
/// CAS via `compare_and_swap` ensures only the *first* datagram across all
/// workers wins, and every subsequent foreign source (per-worker view) is
/// dropped at the listener.
pub type SharedLockedSource = Arc<ArcSwapOption<SocketAddr>>;

/// Process-wide exit code. Defaulted to 0; bumped to 1 by any worker FSM
/// that hits a terminal-with-EXIT_ON_FAILURE branch. `main.rs` reads this
/// after every worker thread has joined and calls `process::exit` with the
/// observed code. This replaces a direct `process::exit(1)` in the FSM that
/// would skip the WS Close 1001 handshake on peer workers.
pub type SharedExitCode = Arc<AtomicI32>;

/// Visible client states (label values for `streamsockets_client_state`).
///
/// Under §10.1 always-reconnect policy the `Terminated` state no longer
/// exists: every disconnect routes either to clean process exit
/// (`EXIT_ON_FAILURE=true`) or back into Reconnecting. The historical
/// `"terminal"` label value is intentionally absent from the label
/// allowlist in `set_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    Connecting,
    Authenticating,
    Live,
    Reconnecting,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::Idle => "disconnected",
            State::Connecting => "connecting",
            State::Authenticating => "authenticating",
            State::Live => "live",
            State::Reconnecting => "reconnecting",
        }
    }
}

pub async fn run_fsm(cfg: Arc<ClientConfig>, shutdown: CancellationToken) -> anyhow::Result<()> {
    let bind_addr: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.bind_port).parse()?;
    let udp = build_listener_udp(bind_addr)?;
    let locked: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    let exit_code: SharedExitCode = Arc::new(AtomicI32::new(0));
    run_fsm_with_socket(cfg, shutdown, udp, 0, locked, exit_code).await
}

/// Per-core FSM entrypoint. Accepts a pre-bound UDP listener (built in `main()`
/// with SO_REUSEPORT alongside the other workers' sockets) and a `worker_idx`.
///
/// `worker_idx == 0` is the singleton-owning worker: it fires
/// `sd_notify(READY=1)` after its first transition to `Live` and starts the
/// systemd watchdog heartbeat.
pub async fn run_fsm_with_socket(
    cfg: Arc<ClientConfig>,
    shutdown: CancellationToken,
    udp: tokio::net::UdpSocket,
    worker_idx: usize,
    locked_source: SharedLockedSource,
    exit_code: SharedExitCode,
) -> anyhow::Result<()> {
    let metrics = streamsockets_metrics::Metrics::global();
    set_state(&metrics, State::Idle);

    let udp = Arc::new(udp);
    if let Ok(local) = udp.local_addr() {
        info!(worker = worker_idx, %local, "udp listener up (SO_REUSEPORT where supported)");
    }

    if worker_idx == 0 {
        streamsockets_core::spawn_watchdog_heartbeat(Duration::from_secs(10));
    }

    let queue = Arc::new(Mutex::new(ReconnectQueue::new(
        cfg.queue_max_bytes,
        cfg.queue_max_packets,
    )));
    let last_udp_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    // Bounded UDP-listener → FSM channel (spec §6.3 — was `unbounded` and could
    // OOM the client under burst). Capacity from cfg.udp_channel_capacity.
    let cap = cfg.udp_channel_capacity.max(1);
    let (udp_tx, udp_rx) = tokio::sync::mpsc::channel::<Bytes>(cap);

    let listener_token = shutdown.child_token();
    let udp_for_listener = udp.clone();
    let locked_for_listener = locked_source.clone();
    let last_udp_for_listener = last_udp_at.clone();
    let metrics_for_listener = metrics.clone();
    let listener_token_clone = listener_token.clone();
    let account_for_listener = "client".to_string();
    let max_frame_for_listener = cfg.max_frame_size;
    let listener_handle = tokio::spawn(async move {
        listener_loop(
            udp_for_listener,
            locked_for_listener,
            last_udp_for_listener,
            metrics_for_listener,
            udp_tx,
            listener_token_clone,
            account_for_listener,
            max_frame_for_listener,
        )
        .await
    });

    // Body wrapped in an inner async block so every exit path falls through
    // to the listener cleanup at the bottom (fix #3: previously the
    // reconnect-loop's `shutdown.cancelled() => return Ok(())` arm leaked the
    // listener task because cleanup lived after the outer loop).
    let result = run_fsm_inner(
        cfg.clone(),
        shutdown.clone(),
        udp.clone(),
        queue.clone(),
        locked_source.clone(),
        last_udp_at.clone(),
        udp_rx,
        worker_idx,
        exit_code.clone(),
    )
    .await;

    listener_token.cancel();
    let _ = listener_handle.await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_fsm_inner(
    cfg: Arc<ClientConfig>,
    shutdown: CancellationToken,
    udp: Arc<UdpSocket>,
    queue: Arc<Mutex<ReconnectQueue>>,
    locked_source: SharedLockedSource,
    last_udp_at: Arc<Mutex<Option<Instant>>>,
    udp_rx: tokio::sync::mpsc::Receiver<Bytes>,
    worker_idx: usize,
    exit_code: SharedExitCode,
) -> anyhow::Result<()> {
    let metrics = streamsockets_metrics::Metrics::global();
    let mut udp_rx = udp_rx;
    let mut ready_sent = false;

    // Idle until first UDP packet (§6.1) or shutdown.
    let first_payload = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        recv = udp_rx.recv() => recv,
    };
    let first_payload = match first_payload {
        Some(p) => p,
        None => {
            error!("udp listener channel closed unexpectedly");
            return Ok(());
        }
    };
    {
        let mut q = queue.lock();
        let dropped = q.push(first_payload);
        if dropped > 0 {
            metrics
                .queue_dropped
                .with_label_values(&["client", "overflow"])
                .inc_by(dropped as f64);
        }
    }

    let account = "client".to_string();
    let mut backoff = Backoff::new(cfg.retry_initial(), cfg.retry_max());
    let mut consecutive_failures: u32 = 0;
    let mut epoch: u64 = 0;

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        epoch = epoch.wrapping_add(1);
        let attempt = shutdown.child_token();

        // Connecting → Authenticating (FSM state metric).
        // The CancellationToken `attempt` covers the entire Connecting →
        // Authenticating → Live arc — minted once per epoch, dropped on
        // transition out of Live or on dial failure.
        set_state(&metrics, State::Connecting);
        info!(epoch, "connecting to {}", cfg.websocket_uri);
        let metrics_for_auth = metrics.clone();
        let on_authenticating = move || {
            // FSM invariant (§6.1 Authenticating): "TCP up, waiting for 101;
            // queue still accepting writes." Queue writes happen in the
            // outer select over `udp_rx.recv()` which is independent of this
            // arc, so the invariant is preserved by construction.
            set_state(&metrics_for_auth, State::Authenticating);
            debug!(epoch, "transport up; awaiting 101");
        };
        let dial_result = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            r = ws::dial_with_progress(&cfg, on_authenticating) => r,
        };
        match dial_result {
            Ok(ws) => {
                consecutive_failures = 0;
                backoff.reset();
                set_state(&metrics, State::Live);
                if worker_idx == 0 && !ready_sent {
                    streamsockets_core::sd_notify_ready();
                    ready_sent = true;
                }
                info!(epoch, "websocket live");
                metrics
                    .reconnect_state
                    .with_label_values(&[&account])
                    .set(0.0);
                let live_outcome = run_live(
                    cfg.clone(),
                    ws,
                    udp.clone(),
                    queue.clone(),
                    locked_source.clone(),
                    last_udp_at.clone(),
                    &mut udp_rx,
                    &account,
                    &shutdown,
                    &attempt,
                    epoch,
                )
                .await;
                attempt.cancel();

                match live_outcome {
                    LiveExit::ShutdownGraceful => {
                        info!("shutdown received; tunnel closed");
                        break;
                    }
                    LiveExit::Idle => {
                        // UDP idle timeout: stay Idle, wait for next UDP traffic OR shutdown.
                        set_state(&metrics, State::Idle);
                        metrics.udp_idle_closes.inc();
                        info!("udp idle; waiting for traffic before reconnecting");
                        let next = tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => break,
                            r = udp_rx.recv() => r,
                        };
                        match next {
                            Some(p) => {
                                let mut q = queue.lock();
                                let dropped = q.push(p);
                                if dropped > 0 {
                                    metrics
                                        .queue_dropped
                                        .with_label_values(&[&account, "overflow"])
                                        .inc_by(dropped as f64);
                                }
                            }
                            None => break,
                        }
                        continue;
                    }
                    LiveExit::CloseTerminal(code) => {
                        // §10.1: under the always-reconnect contract this is
                        // no longer terminal. The log line is preserved (the
                        // peer DID send a terminal-class code) but the
                        // disposition is "exit-on-failure or reconnect".
                        warn!(
                            code,
                            "received terminal close; routing through always-reconnect policy"
                        );
                        if handle_disconnect_should_exit(
                            &cfg,
                            &exit_code,
                            &shutdown,
                            &format!("terminal close code {code}"),
                        ) {
                            return Ok(());
                        }
                        metrics
                            .reconnect_attempts
                            .with_label_values(&[&account])
                            .inc();
                    }
                    LiveExit::Transient(reason) => {
                        // §10.1: under the always-reconnect contract,
                        // EXIT_ON_FAILURE=true exits on ANY disconnect —
                        // not just CloseTerminal-class. A 1011, 1000,
                        // TCP RST, or ping-timeout disconnect under
                        // EXIT_ON_FAILURE=true also signals exit 1.
                        warn!(epoch, "tunnel disconnected: {reason}; reconnecting");
                        if handle_disconnect_should_exit(
                            &cfg,
                            &exit_code,
                            &shutdown,
                            &format!("transient disconnect: {reason}"),
                        ) {
                            return Ok(());
                        }
                        metrics
                            .reconnect_attempts
                            .with_label_values(&[&account])
                            .inc();
                    }
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                // §10.1: under always-reconnect, EXIT_ON_FAILURE=true exits
                // on ANY dial failure — terminal (401/403) and transient
                // (TCP RST, ECONNREFUSED, TLS handshake fail, …) alike.
                // The "terminal" classification is preserved only for the
                // log message; the policy branch is the same.
                let kind = if e.is_terminal() {
                    "terminal"
                } else {
                    "transient"
                };
                if handle_disconnect_should_exit(
                    &cfg,
                    &exit_code,
                    &shutdown,
                    &format!("dial failed {kind}: {e}"),
                ) {
                    return Ok(());
                }
                metrics
                    .reconnect_attempts
                    .with_label_values(&[&account])
                    .inc();
            }
        }

        // Reconnecting
        set_state(&metrics, State::Reconnecting);
        metrics
            .reconnect_state
            .with_label_values(&[&account])
            .set(1.0);

        if consecutive_failures >= cfg.retry_budget {
            // §10.1: RETRY_BUDGET is the only hard ceiling on a reconnect
            // storm. When exhausted the worker exits — cleanly under
            // EXIT_ON_FAILURE=false (exit code 0) or with code 1 under
            // EXIT_ON_FAILURE=true. There is no "Idle-after-Terminated"
            // state to fall into anymore.
            warn!(
                consecutive_failures,
                "retry budget exhausted; worker exiting"
            );
            if cfg.exit_on_failure {
                error!("EXIT_ON_FAILURE=true; signalling exit 1 across workers");
                exit_code.store(1, Ordering::SeqCst);
                shutdown.cancel();
            }
            return Ok(());
        }

        let drain_deadline = Instant::now() + cfg.drain_timeout();
        let delay = backoff.next_delay();
        info!(?delay, "backoff delay");
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                _ = &mut sleep => break,
                maybe = udp_rx.recv() => {
                    match maybe {
                        Some(p) => {
                            let mut q = queue.lock();
                            let dropped = q.push(p);
                            if dropped > 0 {
                                metrics
                                    .queue_dropped
                                    .with_label_values(&[&account, "overflow"])
                                    .inc_by(dropped as f64);
                            }
                            metrics.queue_depth_bytes.with_label_values(&[&account]).set(q.len_bytes() as f64);
                            metrics.queue_depth_packets.with_label_values(&[&account]).set(q.len_packets() as f64);
                        }
                        None => return Ok(()),
                    }
                }
            }
        }

        if Instant::now() >= drain_deadline {
            let mut q = queue.lock();
            let n = q.purge();
            if n > 0 {
                metrics.queue_purged.with_label_values(&[&account]).inc();
                metrics
                    .queue_depth_bytes
                    .with_label_values(&[&account])
                    .set(0.0);
                metrics
                    .queue_depth_packets
                    .with_label_values(&[&account])
                    .set(0.0);
                metrics
                    .queue_dropped
                    .with_label_values(&[&account, "drain_timeout"])
                    .inc_by(n as f64);
                warn!(purged = n, "drain timeout reached; purged queue");
            }
        }
    }

    Ok(())
}

enum LiveExit {
    Idle,
    Transient(String),
    CloseTerminal(u16),
    ShutdownGraceful,
}

#[allow(clippy::too_many_arguments)]
async fn run_live(
    cfg: Arc<ClientConfig>,
    ws: ws::WsHandle,
    udp: Arc<UdpSocket>,
    queue: Arc<Mutex<ReconnectQueue>>,
    locked: SharedLockedSource,
    last_udp_at: Arc<Mutex<Option<Instant>>>,
    udp_rx: &mut tokio::sync::mpsc::Receiver<Bytes>,
    account: &str,
    shutdown: &CancellationToken,
    _attempt: &CancellationToken,
    _epoch: u64,
) -> LiveExit {
    let metrics = streamsockets_metrics::Metrics::global();
    // Bound the per-message reassembly buffer to MAX_FRAME_SIZE × 2 (spec §5.3).
    // Without this, fastwebsockets defaults to 64 MiB and a malicious or
    // compromised server can drive client memory via continuation reassembly.
    let mut ws_inner = ws;
    ws_inner.set_max_message_size(cfg.max_frame_size * 2);
    ws_inner.set_auto_close(true);
    ws_inner.set_auto_pong(true);
    ws_inner.set_writev(false);
    let mut ws = FragmentCollector::new(ws_inner);

    // Flush queue first (FIFO).
    {
        let frames: Vec<Bytes> = {
            let mut q = queue.lock();
            let mut v = Vec::new();
            while let Some(b) = q.pop_front() {
                v.push(b);
            }
            metrics
                .queue_depth_bytes
                .with_label_values(&[account])
                .set(0.0);
            metrics
                .queue_depth_packets
                .with_label_values(&[account])
                .set(0.0);
            v
        };
        for b in frames {
            if let Err(e) = ws
                .write_frame(Frame::binary(Payload::Owned(b.to_vec())))
                .await
            {
                return LiveExit::Transient(format!("ws write: {e}"));
            }
        }
    }

    let ping_interval = cfg.ping_interval();
    let ping_timeout = cfg.ping_timeout();
    let permitted_misses = cfg.ping_permitted_misses;
    let mut ping_iv = tokio::time::interval(ping_interval);
    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_iv.tick().await; // skip immediate fire

    // Initial pong deadline armed at first ping fire + ping_timeout (spec-compliant
    // semantics; previously fsm.rs:273 armed it at `now + ping_timeout` which
    // could fire before the first ping/pong cycle and trip a spurious miss when
    // ping_timeout < ping_interval).
    let pong_deadline = tokio::time::sleep(ping_interval + ping_timeout);
    tokio::pin!(pong_deadline);
    let mut missed_pongs: u32 = 0;
    // (Fix #20) Ping/Pong payload pairing. RFC 6455 §5.5.3 requires the Pong
    // to echo the Ping payload. We use a monotonic u64 written network-order
    // as the payload; on Pong arrival the echoed payload must match the
    // last_ping_payload snapshot, otherwise we treat it as a stale Pong
    // and do not compute RTT or clear miss-count.
    let mut last_ping_sent: Option<(Instant, [u8; 8])> = None;
    let mut ping_seq: u64 = 0;

    let udp_idle_deadline = tokio::time::sleep(cfg.udp_timeout());
    tokio::pin!(udp_idle_deadline);
    let bump_idle = || cfg.udp_timeout();

    loop {
        tokio::select! {
            // Shutdown signal: send WS Close 1001, allow brief drain, then return.
            // We `return` immediately so the arm fires at most once.
            _ = shutdown.cancelled() => {
                // Drain any UDP frames buffered in `udp_rx` before we send the
                // Close frame and walk away — otherwise data the listener
                // already received but hadn't pumped through is silently
                // dropped during the 2 s grace window. Bound by a 500 ms wall
                // clock so a stuck producer can't hold up shutdown.
                let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                loop {
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(drain_deadline) => break,
                        msg = udp_rx.recv() => {
                            match msg {
                                Some(payload) => {
                                    if ws
                                        .write_frame(Frame::binary(Payload::Owned(payload.to_vec())))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
                let _ = ws.write_frame(Frame::close(1001, b"client going away")).await;
                debug!("sent 1001 on shutdown");
                tokio::time::sleep(Duration::from_secs(2)).await;
                return LiveExit::ShutdownGraceful;
            }
            // 1) UDP from listener channel → ws
            maybe = udp_rx.recv() => {
                match maybe {
                    Some(payload) => {
                        udp_idle_deadline.as_mut().reset(tokio::time::Instant::now() + bump_idle());
                        *last_udp_at.lock() = Some(Instant::now());
                        if let Err(e) = ws.write_frame(Frame::binary(Payload::Owned(payload.to_vec()))).await {
                            return LiveExit::Transient(format!("ws write: {e}"));
                        }
                    }
                    None => return LiveExit::Transient("udp listener closed".into()),
                }
            }
            // 2) Frame from server → UDP (locked source)
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => match frame.opcode {
                        OpCode::Binary => {
                            let bytes = frame.payload.to_owned();
                            if let Err(e) = send_udp_to_locked(&udp, &locked, &bytes).await {
                                debug!("udp send err: {e}");
                            }
                        }
                        OpCode::Pong => {
                            // (Fix #20) Validate the Pong echoes the most recent Ping payload.
                            // A spurious or replayed Pong (no matching Ping in flight, or
                            // payload mismatch) must not clear the miss-count or skew RTT.
                            let echoed = frame.payload.as_ref();
                            match last_ping_sent.as_ref() {
                                Some((sent_at, expected)) if echoed == expected.as_slice() => {
                                    let rtt = sent_at.elapsed().as_secs_f64();
                                    metrics.ping_rtt_seconds.with_label_values(&[account]).observe(rtt);
                                    last_ping_sent = None;
                                    missed_pongs = 0;
                                    // Re-arm the deadline for the FULL next
                                    // cycle (next ping fire + ping_timeout).
                                    // Previously this set `now + ping_timeout`,
                                    // which fired before the next ping when
                                    // ping_timeout < ping_interval and tripped
                                    // a spurious miss.
                                    pong_deadline
                                        .as_mut()
                                        .reset(tokio::time::Instant::now() + ping_interval + ping_timeout);
                                }
                                _ => {
                                    debug!(echoed_len = echoed.len(), "ignoring unmatched Pong payload");
                                }
                            }
                        }
                        OpCode::Ping => {
                            // fastwebsockets auto-pong handles this.
                        }
                        OpCode::Close => {
                            // (§3.1.1) Path A — peer (or intermediary) sent
                            // a Close frame. Log the full payload so the
                            // operator can chase what actually arrived
                            // on the wire (proxy hiccup vs. server-asserted
                            // close) without needing tcpdump.
                            let payload = frame.payload.as_ref();
                            let code = parse_close_code(payload);
                            let reason = if payload.len() > 2 {
                                String::from_utf8_lossy(&payload[2..]).into_owned()
                            } else {
                                String::new()
                            };
                            info!(
                                code,
                                reason = %reason,
                                source = "wire",
                                "received Close frame from peer"
                            );
                            metrics.ws_close.with_label_values(&["server", &code.to_string()]).inc();
                            // §10.1: under always-reconnect, 1003/1008/1002
                            // are no longer wired to a separate terminal
                            // policy here. The CloseTerminal variant is
                            // preserved so the outer arm can log "received
                            // terminal close" — the disposition is decided
                            // there (EXIT_ON_FAILURE vs reconnect).
                            if matches!(code, 1003 | 1008 | 1002) {
                                return LiveExit::CloseTerminal(code);
                            }
                            return LiveExit::Transient(format!("close: {code}"));
                        }
                        OpCode::Text => {
                            metrics.protocol_violations.with_label_values(&["text_frame"]).inc();
                            return LiveExit::CloseTerminal(1003);
                        }
                        OpCode::Continuation => {
                            // FragmentCollector should have absorbed this;
                            // a raw Continuation here is a peer protocol bug.
                            // §3.1.2 source label so this is distinguishable
                            // from a wire-level Close in operator logs.
                            warn!(
                                source = "local-decode",
                                variant = "raw_continuation",
                                "received raw Continuation opcode after FragmentCollector; \
                                 synthesizing close code 1002"
                            );
                            metrics.protocol_violations.with_label_values(&["continuation"]).inc();
                            return LiveExit::CloseTerminal(1002);
                        }
                    },
                    Err(e) => {
                        // (Fix #21 / §3.1.2) Match on WebSocketError
                        // variants instead of string-sniffing Display.
                        // Spec §5.3: "Any other frame opcode (RSV bits set,
                        // unknown opcode): close 1002 (Protocol Error)."
                        //
                        // §3.1.2 diagnostic upgrade: when fastwebsockets
                        // returns a protocol-class decode error the client
                        // historically *synthesized* a 1002 close code and
                        // logged it identically to a wire-level Close(1002)
                        // from the peer. Operators chasing the bug had no
                        // way to tell Path A from Path B. We now:
                        //   - log the exact variant (low-cardinality label),
                        //   - mark `source = "local-decode"` so the log line
                        //     is unambiguously distinct from §3.1.1's wire
                        //     case,
                        //   - label `protocol_violations` per-variant rather
                        //     than the single bucket `"frame_format"`.
                        let variant = ws_error_variant(&e);
                        let is_protocol = matches!(
                            &e,
                            WebSocketError::ReservedBitsNotZero
                                | WebSocketError::InvalidFragment
                                | WebSocketError::InvalidContinuationFrame
                                | WebSocketError::ControlFrameFragmented
                                | WebSocketError::PingFrameTooLarge
                                | WebSocketError::FrameTooLarge
                                | WebSocketError::InvalidValue
                                | WebSocketError::InvalidCloseFrame
                                | WebSocketError::InvalidCloseCode
                                | WebSocketError::InvalidUTF8
                        );
                        if is_protocol {
                            warn!(
                                variant,
                                error = %e,
                                source = "local-decode",
                                "WebSocket read returned a protocol-error variant; the close \
                                 code reported to operators (1002) is synthesized by this client \
                                 and NOT a wire-level Close from the peer"
                            );
                            metrics
                                .protocol_violations
                                .with_label_values(&[variant])
                                .inc();
                            // §10.1: under always-reconnect this still
                            // flags the read as terminal-class (the
                            // outer arm decides policy), but the §10.1
                            // policy turns "terminal-class" into a
                            // reconnect unless EXIT_ON_FAILURE=true.
                            return LiveExit::CloseTerminal(1002);
                        }
                        return LiveExit::Transient(format!("ws read: {e}"));
                    }
                }
            }
            // 3) Send a ping with a monotonic-counter payload (fix #20).
            _ = ping_iv.tick() => {
                ping_seq = ping_seq.wrapping_add(1);
                let payload_bytes = ping_seq.to_be_bytes();
                last_ping_sent = Some((Instant::now(), payload_bytes));
                if let Err(e) = ws
                    .write_frame(Frame::new(true, OpCode::Ping, None, Payload::Borrowed(&payload_bytes)))
                    .await
                {
                    return LiveExit::Transient(format!("ws ping write: {e}"));
                }
            }
            // 4) Pong deadline
            _ = &mut pong_deadline => {
                // If no ping is currently outstanding, the deadline fired
                // because we haven't reached the next ping interval — this
                // is a config bug (ping_timeout < ping_interval) but the
                // safe thing is to wait the full cycle, not count a miss.
                if last_ping_sent.is_none() {
                    pong_deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + ping_interval + ping_timeout);
                    continue;
                }
                missed_pongs += 1;
                metrics.ping_timeouts.with_label_values(&[account]).inc();
                warn!(missed_pongs, permitted_misses, "ping deadline missed");
                if missed_pongs > permitted_misses {
                    return LiveExit::Transient("ping timeout".into());
                }
                pong_deadline.as_mut().reset(tokio::time::Instant::now() + ping_timeout);
            }
            // 5) UDP idle
            _ = &mut udp_idle_deadline => {
                let _ = ws.write_frame(Frame::close(1000, b"udp idle")).await;
                return LiveExit::Idle;
            }
        }
    }
}

fn build_listener_udp(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        if bind.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        let _ = sock.set_reuse_port(true);
    }
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    sock.bind(&bind.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

async fn send_udp_to_locked(
    udp: &UdpSocket,
    locked: &SharedLockedSource,
    payload: &[u8],
) -> std::io::Result<()> {
    let snap = locked.load();
    let target = match snap.as_ref() {
        Some(a) => **a,
        None => return Ok(()),
    };
    udp.send_to(payload, target).await.map(|_| ())
}

fn parse_close_code(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        1005 // No Status Rcvd
    }
}

fn set_state(metrics: &streamsockets_metrics::Metrics, s: State) {
    // §10.1: `"terminal"` is intentionally absent — the Terminated state
    // no longer exists in the FSM. Existing dashboards that selected on
    // `state="terminal"` will see the series go absent (not flip to 0).
    for label in [
        "disconnected",
        "connecting",
        "authenticating",
        "live",
        "reconnecting",
    ] {
        metrics
            .client_state
            .with_label_values(&[label])
            .set(if label == s.label() { 1.0 } else { 0.0 });
    }
}

/// §10.1 disconnect policy: returns `true` if the worker should return
/// cleanly (`EXIT_ON_FAILURE=true`), `false` if the caller should fall
/// through to the reconnect loop.
///
/// Replaces the v2.1.0 `terminate()` helper. Under always-reconnect there
/// is no Terminated state to enter and no Idle-after-Terminated to wait in;
/// the caller continues the outer loop on `false`.
///
/// Exit-on-failure propagation:
///   - SeqCst store on `exit_code` so any later observer that reads it
///     after observing `shutdown.is_cancelled()` is guaranteed to see 1.
///     AcqRel would be enough on x86 but the cross-arch story is cleaner
///     with SeqCst (matches Fix #2's original rationale).
///   - `shutdown.cancel()` broadcasts to peer workers so their `select!`
///     arms wake and they drain gracefully (no SIGKILL via `process::exit`).
fn handle_disconnect_should_exit(
    cfg: &ClientConfig,
    exit_code: &SharedExitCode,
    shutdown: &CancellationToken,
    reason: &str,
) -> bool {
    if cfg.exit_on_failure {
        error!(
            reason,
            "EXIT_ON_FAILURE=true; signalling exit 1 across workers"
        );
        exit_code.store(1, Ordering::SeqCst);
        shutdown.cancel();
        return true;
    }
    warn!(reason, "disconnect; reconnecting after backoff");
    false
}

/// Human-readable label for a `WebSocketError` variant. Low-cardinality
/// (≤ ~12 values across the closed set) so it is safe to use as a
/// Prometheus label value on `protocol_violations_total{reason}`.
///
/// Added in §3.1.2: previously the client logged every protocol decode
/// error identically as "code 1002", indistinguishable from a wire-level
/// Close(1002). The variant string makes Path A vs Path B
/// distinguishable in both logs and metrics.
fn ws_error_variant(e: &WebSocketError) -> &'static str {
    match e {
        WebSocketError::ReservedBitsNotZero => "reserved_bits_not_zero",
        WebSocketError::InvalidFragment => "invalid_fragment",
        WebSocketError::InvalidContinuationFrame => "invalid_continuation",
        WebSocketError::ControlFrameFragmented => "control_frame_fragmented",
        WebSocketError::PingFrameTooLarge => "ping_frame_too_large",
        WebSocketError::FrameTooLarge => "frame_too_large",
        WebSocketError::InvalidValue => "invalid_value",
        WebSocketError::InvalidCloseFrame => "invalid_close_frame",
        WebSocketError::InvalidCloseCode => "invalid_close_code",
        WebSocketError::InvalidUTF8 => "invalid_utf8",
        _ => "other",
    }
}

#[allow(clippy::too_many_arguments)]
async fn listener_loop(
    udp: Arc<UdpSocket>,
    locked_source: SharedLockedSource,
    last_udp_at: Arc<Mutex<Option<Instant>>>,
    metrics: Arc<streamsockets_metrics::Metrics>,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    account: String,
    max_frame_size: usize,
) {
    // Buffer sized to the absolute UDP datagram ceiling (u16 length field).
    // Per-frame size is enforced after recv via `n > max_frame_size`.
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            r = udp.recv_from(&mut buf) => {
                match r {
                    Ok((n, peer)) => {
                        // (Fix #4) Enforce MAX_FRAME_SIZE at the listener.
                        // Anything larger than the configured cap cannot be
                        // legitimately forwarded; drop and count.
                        if n > max_frame_size {
                            metrics
                                .queue_dropped
                                .with_label_values(&[&account, "oversize"])
                                .inc();
                            debug!(received = n, max = max_frame_size, "dropping oversize UDP datagram");
                            continue;
                        }
                        // (Fix #5) Process-shared lock-on via ArcSwapOption +
                        // CAS-style first-write-wins. `compare_and_swap` is
                        // not available on ArcSwapOption directly, so we do a
                        // load-test-then-rcu pattern: snapshot, if empty
                        // attempt rcu-store. `rcu` retries on contention so
                        // exactly one peer wins across all workers.
                        let snap = locked_source.load();
                        match snap.as_ref() {
                            None => {
                                let new_arc = Arc::new(peer);
                                let prev = locked_source.compare_and_swap(&None::<Arc<SocketAddr>>, Some(new_arc.clone()));
                                if prev.is_none() {
                                    info!(peer = %peer, "first UDP packet — locking source (process-wide)");
                                } else if let Some(prev_addr) = prev.as_ref() {
                                    if **prev_addr != peer {
                                        metrics.client_foreign_sources.inc();
                                        debug!(peer = %peer, "dropping foreign UDP source (lost CAS)");
                                        continue;
                                    }
                                }
                            }
                            Some(addr) if **addr == peer => {}
                            Some(_) => {
                                metrics.client_foreign_sources.inc();
                                debug!(peer = %peer, "dropping foreign UDP source");
                                continue;
                            }
                        }
                        *last_udp_at.lock() = Some(Instant::now());
                        let payload = Bytes::copy_from_slice(&buf[..n]);
                        // try_send is non-blocking; on Full we drop and count as
                        // channel-overflow so a slow consumer cannot OOM the listener.
                        match tx.try_send(payload) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                metrics
                                    .queue_dropped
                                    .with_label_values(&[&account, "channel_full"])
                                    .inc();
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                        }
                    }
                    Err(e) => {
                        warn!("udp recv error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}
