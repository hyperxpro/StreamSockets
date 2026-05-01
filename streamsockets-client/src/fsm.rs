//! Reconnect FSM: Idle → Connecting → Authenticating → Live ⇄ Reconnecting → Terminated.
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
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backoff::Backoff;
use crate::queue::ReconnectQueue;
use crate::ws::{self};
use crate::ClientConfig;

/// Visible client states (label values for `streamsockets_client_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    Connecting,
    Authenticating,
    Live,
    Reconnecting,
    Terminated,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::Idle => "disconnected",
            State::Connecting => "connecting",
            State::Authenticating => "authenticating",
            State::Live => "live",
            State::Reconnecting => "reconnecting",
            State::Terminated => "terminal",
        }
    }
}

pub async fn run_fsm(cfg: Arc<ClientConfig>, shutdown: CancellationToken) -> anyhow::Result<()> {
    let bind_addr: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.bind_port).parse()?;
    let udp = build_listener_udp(bind_addr)?;
    run_fsm_with_socket(cfg, shutdown, udp, 0).await
}

/// Per-core FSM entrypoint. Accepts a pre-bound UDP listener (built in `main()`
/// with SO_REUSEPORT alongside the other workers' sockets) and a `worker_idx`.
///
/// `worker_idx == 0` is the singleton-owning worker: it fires
/// `sd_notify(READY=1)` after its first transition to `Live` (per
/// MIGRATION.md §12.2) and starts the systemd watchdog heartbeat.
pub async fn run_fsm_with_socket(
    cfg: Arc<ClientConfig>,
    shutdown: CancellationToken,
    udp: tokio::net::UdpSocket,
    worker_idx: usize,
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

    let queue = Arc::new(Mutex::new(ReconnectQueue::new(cfg.queue_max_bytes)));
    let locked_source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
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
    let listener_handle = tokio::spawn(async move {
        listener_loop(
            udp_for_listener,
            locked_for_listener,
            last_udp_for_listener,
            metrics_for_listener,
            udp_tx,
            listener_token_clone,
            account_for_listener,
        )
        .await
    });

    let mut udp_rx = udp_rx;
    // sd_notify(READY=1): per MIGRATION.md §12.2 the client signals READY after
    // its first transition to Live (not on listener bind — bind succeeds before
    // we have anything to forward). Fired exactly once, from worker-0 only.
    let mut ready_sent = false;

    // Idle until first UDP packet (§6.1) or shutdown.
    let first_payload = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            listener_token.cancel();
            let _ = listener_handle.await;
            return Ok(());
        }
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
        // Authenticating → Live arc per MIGRATION.md §6.6 — minted once per
        // epoch, dropped on transition out of Live or on dial failure.
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
                        warn!(code, "received terminal close; entering Terminated");
                        if !terminate(&cfg, &metrics, &account) {
                            // Stay Idle waiting for new traffic per §6.5 ("else: stay Idle, log").
                            return wait_idle_until_shutdown(&shutdown, &mut udp_rx).await;
                        }
                        return Ok(());
                    }
                    LiveExit::Transient(reason) => {
                        warn!(epoch, "tunnel disconnected: {reason}; reconnecting");
                        metrics
                            .reconnect_attempts
                            .with_label_values(&[&account])
                            .inc();
                    }
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                if e.is_terminal() {
                    warn!("dial failed terminal: {e}");
                    if !terminate(&cfg, &metrics, &account) {
                        return wait_idle_until_shutdown(&shutdown, &mut udp_rx).await;
                    }
                    return Ok(());
                }
                warn!("dial failed transient: {e}");
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
            warn!(consecutive_failures, "retry budget exhausted; terminating");
            if !terminate(&cfg, &metrics, &account) {
                return wait_idle_until_shutdown(&shutdown, &mut udp_rx).await;
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
                    .queue_dropped
                    .with_label_values(&[&account, "drain_timeout"])
                    .inc_by(n as f64);
                warn!(purged = n, "drain timeout reached; purged queue");
            }
        }
    }

    listener_token.cancel();
    let _ = listener_handle.await;
    Ok(())
}

async fn wait_idle_until_shutdown(
    shutdown: &CancellationToken,
    udp_rx: &mut tokio::sync::mpsc::Receiver<Bytes>,
) -> anyhow::Result<()> {
    let metrics = streamsockets_metrics::Metrics::global();
    set_state(&metrics, State::Terminated);
    info!("entering Idle-after-Terminated; awaiting shutdown");
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            // Drain incoming UDP packets so the listener channel doesn't fill up.
            _ = udp_rx.recv() => {}
        }
    }
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
    _locked: Arc<Mutex<Option<SocketAddr>>>,
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
    let mut last_ping_sent: Option<Instant> = None;

    let udp_idle_deadline = tokio::time::sleep(cfg.udp_timeout());
    tokio::pin!(udp_idle_deadline);
    let bump_idle = || cfg.udp_timeout();

    loop {
        tokio::select! {
            // Shutdown signal: send WS Close 1001, allow brief drain, then return.
            // We `return` immediately so the arm fires at most once.
            _ = shutdown.cancelled() => {
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
                            if let Err(e) = send_udp_to_locked(&udp, &_locked, &bytes).await {
                                debug!("udp send err: {e}");
                            }
                        }
                        OpCode::Pong => {
                            if let Some(sent) = last_ping_sent.take() {
                                let rtt = sent.elapsed().as_secs_f64();
                                metrics.ping_rtt_seconds.with_label_values(&[account]).observe(rtt);
                            }
                            missed_pongs = 0;
                            pong_deadline.as_mut().reset(tokio::time::Instant::now() + ping_timeout);
                        }
                        OpCode::Ping => {
                            // fastwebsockets auto-pong handles this.
                        }
                        OpCode::Close => {
                            let code = parse_close_code(frame.payload.as_ref());
                            metrics.ws_close.with_label_values(&["server", &code.to_string()]).inc();
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
                            metrics.protocol_violations.with_label_values(&["continuation"]).inc();
                            return LiveExit::CloseTerminal(1002);
                        }
                    },
                    Err(e) => {
                        // Map fastwebsockets parse / RSV / opcode errors to 1002.
                        // Spec §5.3: "Any other frame opcode (RSV bits set, unknown
                        // opcode): close 1002 (Protocol Error)."
                        let s = e.to_string();
                        let is_protocol = s.contains("RSV") || s.contains("opcode") || s.contains("Reserved");
                        if is_protocol {
                            metrics.protocol_violations.with_label_values(&["frame_format"]).inc();
                            return LiveExit::CloseTerminal(1002);
                        }
                        return LiveExit::Transient(format!("ws read: {e}"));
                    }
                }
            }
            // 3) Send a ping
            _ = ping_iv.tick() => {
                last_ping_sent = Some(Instant::now());
                if let Err(e) = ws.write_frame(Frame::new(true, OpCode::Ping, None, Payload::Borrowed(b"PING"))).await {
                    return LiveExit::Transient(format!("ws ping write: {e}"));
                }
            }
            // 4) Pong deadline
            _ = &mut pong_deadline => {
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
    locked: &Mutex<Option<SocketAddr>>,
    payload: &[u8],
) -> std::io::Result<()> {
    let target = match *locked.lock() {
        Some(a) => a,
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
    for label in [
        "disconnected",
        "connecting",
        "authenticating",
        "live",
        "reconnecting",
        "terminal",
    ] {
        metrics
            .client_state
            .with_label_values(&[label])
            .set(if label == s.label() { 1.0 } else { 0.0 });
    }
}

/// Returns `true` if the process should exit (EXIT_ON_FAILURE=true).
/// Returns `false` if we should fall through to wait-Idle behavior per §6.5.
fn terminate(cfg: &ClientConfig, metrics: &streamsockets_metrics::Metrics, account: &str) -> bool {
    set_state(metrics, State::Terminated);
    metrics
        .reconnect_state
        .with_label_values(&[account])
        .set(2.0);
    if cfg.exit_on_failure {
        error!("EXIT_ON_FAILURE=true; exiting 1");
        std::process::exit(1);
    }
    warn!("terminal but EXIT_ON_FAILURE=false; staying up Idle (spec §6.5)");
    false
}

async fn listener_loop(
    udp: Arc<UdpSocket>,
    locked_source: Arc<Mutex<Option<SocketAddr>>>,
    last_udp_at: Arc<Mutex<Option<Instant>>>,
    metrics: Arc<streamsockets_metrics::Metrics>,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    account: String,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            r = udp.recv_from(&mut buf) => {
                match r {
                    Ok((n, peer)) => {
                        let mut lock = locked_source.lock();
                        match *lock {
                            None => {
                                info!(peer = %peer, "first UDP packet — locking source");
                                *lock = Some(peer);
                                drop(lock);
                            }
                            Some(addr) if addr == peer => {
                                drop(lock);
                            }
                            Some(_) => {
                                drop(lock);
                                metrics.client_foreign_sources.inc();
                                debug!(peer = %peer, "dropping foreign UDP source");
                                continue;
                            }
                        }
                        *last_udp_at.lock() = Some(Instant::now());
                        let payload = Bytes::copy_from_slice(&buf[..n]);
                        // try_send is non-blocking; on Full we drop and count as
                        // overflow so a slow consumer cannot OOM the listener.
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
