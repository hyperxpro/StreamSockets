//! Prometheus metrics + HTTP service for /metrics, /healthz, /livez, /readyz.
//!
//! Mirrors `metrics/src/main/java/.../MetricsRegistry.java`. Preserved metric
//! names + labels are byte-identical to v1; new v2 metrics are additive.

#![warn(missing_docs)]
// Same pedantic-suppression rationale as `streamsockets-core/src/lib.rs`.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::redundant_closure_for_method_calls,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::if_not_else,
    clippy::needless_continue,
    clippy::match_wild_err_arm,
    clippy::map_unwrap_or,
    clippy::should_implement_trait,
    clippy::duplicated_attributes,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unnested_or_patterns,
    clippy::single_match_else,
    clippy::semicolon_if_nothing_returned,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::ignored_unit_patterns
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use once_cell::sync::OnceCell;
use prometheus::{
    register_counter_vec_with_registry, register_counter_with_registry,
    register_gauge_vec_with_registry, register_gauge_with_registry,
    register_histogram_vec_with_registry, Counter, CounterVec, Encoder, Gauge, GaugeVec,
    HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Global metrics registry. Single instance per process — matches Java singleton.
#[allow(missing_docs)] // each field maps 1:1 to a spec'd metric; names are self-documenting
pub struct Metrics {
    /// Underlying prometheus `Registry` — exposed for advanced callers (tests,
    /// custom encoders).
    pub registry: Registry,

    // ── preserved ──────────────────────────────────────────────────────────
    pub active_connections: GaugeVec,
    pub connection_status: GaugeVec,
    pub total_connections: CounterVec,
    pub bytes_received: CounterVec,
    pub bytes_sent: CounterVec,
    pub connection_duration: HistogramVec,

    // ── new v2 ─────────────────────────────────────────────────────────────
    pub handshake_failures: CounterVec,
    pub handshake_version: GaugeVec,
    pub handshake_timeouts: Counter,
    pub tls_handshake_failures: CounterVec,
    pub reconnect_attempts: CounterVec,
    pub reconnect_state: GaugeVec,
    pub ping_timeouts: CounterVec,
    pub ping_rtt_seconds: HistogramVec,
    pub ws_close: CounterVec,
    pub protocol_violations: CounterVec,
    pub upstream_dns_failures: Counter,
    pub upstream_connect_failures: Counter,
    pub upstream_unreachable: Counter,
    pub upstream_send_drops: Counter,
    pub downstream_queue_drops: Counter,
    pub upstream_truncated: Counter,
    pub queue_depth_bytes: GaugeVec,
    pub queue_dropped: CounterVec,
    pub queue_purged: CounterVec,
    pub client_foreign_sources: Counter,
    pub active_tunnels: Gauge,
    pub udp_egress_socket_buffer_bytes: GaugeVec,
    pub runtime_kind: GaugeVec,
    pub client_state: GaugeVec,
    pub udp_idle_closes: Counter,
}

/// Canonical list of every metric the registry exposes. Used by tests to
/// confirm spec coverage and by `cargo test` to detect drift.
///
/// MUST stay in sync with MIGRATION.md §9.1 (preserved) + §9.2 (new) + §13.3
/// (failure-mode catalog: `streamsockets_udp_idle_closes_total`).
pub const ALL_METRIC_NAMES: &[&str] = &[
    // §9.1 preserved
    "streamsockets_active_connections",
    "streamsockets_connection_status",
    "streamsockets_total_connections",
    "streamsockets_bytes_received_total",
    "streamsockets_bytes_sent_total",
    "streamsockets_connection_duration_seconds",
    // §9.2 new
    "streamsockets_handshake_failures_total",
    "streamsockets_handshake_version",
    "streamsockets_handshake_timeouts_total",
    "streamsockets_tls_handshake_failures_total",
    "streamsockets_reconnect_attempts_total",
    "streamsockets_reconnect_state",
    "streamsockets_ping_timeouts_total",
    "streamsockets_ping_rtt_seconds",
    "streamsockets_ws_close_total",
    "streamsockets_protocol_violations_total",
    "streamsockets_upstream_dns_failures_total",
    "streamsockets_upstream_connect_failures_total",
    "streamsockets_upstream_unreachable_total",
    "streamsockets_upstream_send_drops_total",
    "streamsockets_downstream_queue_drops_total",
    "streamsockets_upstream_truncated_total",
    "streamsockets_queue_depth_bytes",
    "streamsockets_queue_dropped_total",
    "streamsockets_queue_purged_total",
    "streamsockets_client_foreign_sources_total",
    "streamsockets_active_tunnels",
    "streamsockets_udp_egress_socket_buffer_bytes",
    "streamsockets_runtime_kind",
    "streamsockets_client_state",
    // §13.3 row 13
    "streamsockets_udp_idle_closes_total",
];

static GLOBAL: OnceCell<Arc<Metrics>> = OnceCell::new();

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        // Preserved metrics — names byte-identical to Java.
        let active_connections = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_active_connections",
                "Number of active WebSocket connections by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let connection_status = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_connection_status",
                "Connection status by account (1 = connected, 0 = disconnected)",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let total_connections = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_total_connections",
                "Total number of connections by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let bytes_received = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_bytes_received_total",
                "Total bytes received from clients by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let bytes_sent = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_bytes_sent_total",
                "Total bytes sent to clients by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let connection_duration = register_histogram_vec_with_registry!(
            HistogramOpts::new(
                "streamsockets_connection_duration_seconds",
                "Connection duration in seconds by account",
            )
            // Spec §9.1 buckets (1s..3600s) extended in v2.0.0 with longer
            // tails (2h, 6h, 24h) so the +Inf bucket isn't the only signal
            // for the long-lived tunnel population. These are additive and
            // do not move existing quantiles.
            // Sub-second buckets prepended so failure-mid-handshake / fast-reject
            // populations don't all collapse into `le=1`.
            .buckets(vec![
                0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0,
                21600.0, 86400.0,
            ]),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");

        // New v2 metrics.
        let handshake_failures = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_handshake_failures_total",
                "Handshake failures by reason",
            ),
            &["reason"],
            registry
        )
        .expect("static metric registration is infallible");
        let handshake_version = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_handshake_version",
                "Handshake version negotiated",
            ),
            &["version"],
            registry
        )
        .expect("static metric registration is infallible");
        let handshake_timeouts = register_counter_with_registry!(
            "streamsockets_handshake_timeouts_total",
            "Handshakes that timed out before completing",
            registry
        )
        .expect("static metric registration is infallible");
        let tls_handshake_failures = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_tls_handshake_failures_total",
                "TLS handshake failures by reason",
            ),
            &["reason"],
            registry
        )
        .expect("static metric registration is infallible");
        let reconnect_attempts = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_reconnect_attempts_total",
                "Total reconnect attempts by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let reconnect_state = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_reconnect_state",
                "Reconnect state (0=Live, 1=Reconnecting, 2=Terminated)",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let ping_timeouts = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_ping_timeouts_total",
                "Total ping timeouts by account",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let ping_rtt_seconds = register_histogram_vec_with_registry!(
            HistogramOpts::new(
                "streamsockets_ping_rtt_seconds",
                "Ping/pong round-trip time in seconds",
            )
            // Sub-millisecond buckets prepended so LAN/intra-DC RTT (typically
            // 100–500 µs) is observable below the historical 1 ms floor.
            .buckets(vec![
                0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                5.0,
            ]),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let ws_close = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_ws_close_total",
                "WebSocket close events by side and code",
            ),
            &["side", "code"],
            registry
        )
        .expect("static metric registration is infallible");
        let protocol_violations = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_protocol_violations_total",
                "Protocol violations by reason",
            ),
            &["reason"],
            registry
        )
        .expect("static metric registration is infallible");
        let upstream_dns_failures = register_counter_with_registry!(
            "streamsockets_upstream_dns_failures_total",
            "Upstream DNS resolution failures",
            registry
        )
        .expect("static metric registration is infallible");
        let upstream_connect_failures = register_counter_with_registry!(
            "streamsockets_upstream_connect_failures_total",
            "Upstream UDP connect() failures",
            registry
        )
        .expect("static metric registration is infallible");
        let upstream_unreachable = register_counter_with_registry!(
            "streamsockets_upstream_unreachable_total",
            "Upstream destination unreachable events (ICMP)",
            registry
        )
        .expect("static metric registration is infallible");
        let upstream_send_drops = register_counter_with_registry!(
            "streamsockets_upstream_send_drops_total",
            "UDP send drops (EAGAIN/ENOBUFS)",
            registry
        )
        .expect("static metric registration is infallible");
        let downstream_queue_drops = register_counter_with_registry!(
            "streamsockets_downstream_queue_drops_total",
            "Frames dropped due to bounded downstream queue full (slow client)",
            registry
        )
        .expect("static metric registration is infallible");
        let upstream_truncated = register_counter_with_registry!(
            "streamsockets_upstream_truncated_total",
            "Upstream UDP datagrams that filled the recv buffer (likely truncated)",
            registry
        )
        .expect("static metric registration is infallible");
        let queue_depth_bytes = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_queue_depth_bytes",
                "Reconnect queue depth in bytes",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let queue_dropped = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_queue_dropped_total",
                "Frames dropped from reconnect queue",
            ),
            &["account_name", "reason"],
            registry
        )
        .expect("static metric registration is infallible");
        let queue_purged = register_counter_vec_with_registry!(
            Opts::new(
                "streamsockets_queue_purged_total",
                "Reconnect queue purges (drain timeout reached)",
            ),
            &["account_name"],
            registry
        )
        .expect("static metric registration is infallible");
        let client_foreign_sources = register_counter_with_registry!(
            "streamsockets_client_foreign_sources_total",
            "UDP packets dropped due to foreign source after lock-on",
            registry
        )
        .expect("static metric registration is infallible");
        let active_tunnels = register_gauge_with_registry!(
            "streamsockets_active_tunnels",
            "Active tunnels (server-wide)",
            registry
        )
        .expect("static metric registration is infallible");
        let udp_egress_socket_buffer_bytes = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_udp_egress_socket_buffer_bytes",
                "Realised UDP socket buffer size in bytes",
            ),
            &["direction"],
            registry
        )
        .expect("static metric registration is infallible");
        let runtime_kind = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_runtime_kind",
                "Selected runtime kind (1 set for active label)",
            ),
            &["kind"],
            registry
        )
        .expect("static metric registration is infallible");
        let client_state = register_gauge_vec_with_registry!(
            Opts::new(
                "streamsockets_client_state",
                "Client FSM state (1 set for active label)",
            ),
            &["state"],
            registry
        )
        .expect("static metric registration is infallible");
        let udp_idle_closes = register_counter_with_registry!(
            "streamsockets_udp_idle_closes_total",
            "Tunnel closes triggered by UDP idle timeout",
            registry
        )
        .expect("static metric registration is infallible");

        Self {
            registry,
            active_connections,
            connection_status,
            total_connections,
            bytes_received,
            bytes_sent,
            connection_duration,
            handshake_failures,
            handshake_version,
            handshake_timeouts,
            tls_handshake_failures,
            reconnect_attempts,
            reconnect_state,
            ping_timeouts,
            ping_rtt_seconds,
            ws_close,
            protocol_violations,
            upstream_dns_failures,
            upstream_connect_failures,
            upstream_unreachable,
            upstream_send_drops,
            downstream_queue_drops,
            upstream_truncated,
            queue_depth_bytes,
            queue_dropped,
            queue_purged,
            client_foreign_sources,
            active_tunnels,
            udp_egress_socket_buffer_bytes,
            runtime_kind,
            client_state,
            udp_idle_closes,
        }
    }

    /// Returns the global singleton, initializing on first call.
    pub fn global() -> Arc<Self> {
        GLOBAL.get_or_init(|| Arc::new(Self::new())).clone()
    }

    /// Convenience wrappers matching Java MetricsRegistry methods.
    ///
    /// Increments `active_connections` + `total_connections` and sets
    /// `connection_status=1` for `account`.
    pub fn record_connection_start(&self, account: &str) {
        self.active_connections.with_label_values(&[account]).inc();
        self.connection_status
            .with_label_values(&[account])
            .set(1.0);
        self.total_connections.with_label_values(&[account]).inc();
    }

    /// Decrements `active_connections`, clears `connection_status`, observes
    /// `connection_duration_seconds` for `account`.
    pub fn record_connection_end(&self, account: &str, duration_seconds: f64) {
        self.active_connections.with_label_values(&[account]).dec();
        self.connection_status
            .with_label_values(&[account])
            .set(0.0);
        self.connection_duration
            .with_label_values(&[account])
            .observe(duration_seconds);
    }

    /// Increment `bytes_received_total` for `account`.
    ///
    /// `bytes` is converted to `f64` for the Prometheus counter; values above
    /// 2^53 (~9 PiB) lose precision. Not a concern at human timescales — at
    /// 10 Gbps it would take ~230 years to roll past 2^53 bytes.
    pub fn record_bytes_received(&self, account: &str, bytes: u64) {
        self.bytes_received
            .with_label_values(&[account])
            .inc_by(bytes as f64);
    }

    /// Increment `bytes_sent_total` for `account`.
    ///
    /// `bytes` is converted to `f64` for the Prometheus counter; values above
    /// 2^53 (~9 PiB) lose precision. See `record_bytes_received` for context.
    pub fn record_bytes_sent(&self, account: &str, bytes: u64) {
        self.bytes_sent
            .with_label_values(&[account])
            .inc_by(bytes as f64);
    }

    /// Encode the registry to Prometheus text format.
    ///
    /// Returns the encoded buffer on success, or the underlying
    /// `prometheus::Error` on encode failure (e.g. an internal mutex was
    /// poisoned). Callers that serve this over HTTP MUST translate `Err` to a
    /// 500; serving a partial body would silently corrupt scrape data.
    pub fn encode_text(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buf)?;
        Ok(buf)
    }
}

/// Lifecycle / health state.
///
/// `ready` flips to true once the **tunnel accept loop** is running (per
/// MIGRATION.md §9.3) — the metrics service does NOT mark itself ready on
/// bind, since /readyz must surface the public-port readiness, not the
/// observability port's.
#[derive(Default)]
pub struct HealthState {
    /// Set when SIGTERM has triggered drain. /healthz returns 503 once true.
    pub draining: AtomicBool,
    /// Set when the public accept loop is running. /readyz returns 200 once
    /// true *and* `draining` is false.
    pub ready: AtomicBool,
}

impl HealthState {
    /// Construct a fresh, not-ready, not-draining state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Flip `ready` true. Caller (server `run()`) calls this *after* the
    /// public TCP listener is bound and accept-looping.
    ///
    /// `Release` is sufficient here — the flag is not paired with other
    /// shared state we need to publish atomically; readers (`is_ready`) only
    /// need to observe the flip itself, which `Acquire` guarantees once
    /// `Release` lands.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Flip `draining` true. Caller (server SIGTERM handler) calls this
    /// before broadcasting graceful shutdown.
    ///
    /// `Release` is sufficient: see `mark_ready` for rationale.
    pub fn mark_draining(&self) {
        self.draining.store(true, Ordering::Release);
    }

    /// True after a `mark_draining` call.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// True after a `mark_ready` call.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Returns a coarse readiness state for operator-facing diagnostics
    /// (used by `/readyz` to distinguish "draining" from "not yet ready").
    #[must_use]
    pub fn state(&self) -> HealthSnapshot {
        // Load draining first: a node that is both ready+draining should be
        // reported as draining (terminal state for shutdown). Acquire orders
        // both loads against the corresponding Release stores.
        let draining = self.draining.load(Ordering::Acquire);
        let ready = self.ready.load(Ordering::Acquire);
        if draining {
            HealthSnapshot::Draining
        } else if ready {
            HealthSnapshot::Ready
        } else {
            HealthSnapshot::NotReady
        }
    }
}

/// Coarse health snapshot, used by `/readyz` to distinguish "still warming
/// up" from "shutting down" for operator triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthSnapshot {
    /// Service has not yet marked itself ready.
    NotReady,
    /// Service is ready and not draining.
    Ready,
    /// Service is draining (terminal state for graceful shutdown).
    Draining,
}

/// Maximum concurrent metrics scrapes. Prometheus typically opens 1-2
/// connections to each /metrics endpoint; 8 is comfortable headroom and a
/// hard ceiling against a noisy or buggy scraper that opens many sockets.
const MAX_CONCURRENT_SCRAPES: usize = 8;

/// Per-connection wall-clock cap on `serve_connection`. Slow-loris guard.
const PER_CONN_DEADLINE: Duration = Duration::from_secs(30);

/// HTTP/1 header read timeout. A scraper that doesn't transmit a complete
/// request line + headers in this window is dropped. Hyper requires a
/// `Timer` to be installed for this to take effect.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Reject a non-loopback bind unless the operator opted in.
///
/// Loopback ⇔ `127.0.0.0/8` (`Ipv4Addr::is_loopback`) or `::1`. Anything else
/// (including `0.0.0.0` and routable addresses) requires `bind_all = true`.
/// Defense in depth: callers in `streamsockets-server` already gate on
/// `METRICS_BIND_ALL`, but a misconfigured embedder could still pass a
/// wildcard `SocketAddr` directly — this check stops that.
fn check_bind_policy(addr: SocketAddr, bind_all: bool) -> std::io::Result<()> {
    if bind_all || addr.ip().is_loopback() {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "metrics_bind_all=false but non-loopback bind requested",
    ))
}

/// Run the metrics HTTP service indefinitely.
///
/// Blocks the calling task; `serve_metrics_with_cancel` is the variant taking
/// a [`tokio_util::sync::CancellationToken`] for graceful shutdown.
///
/// `bind_all` must be `true` to bind a non-loopback address. The default in
/// every caller is `false`; see `check_bind_policy` for the rationale.
pub async fn serve_metrics(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    health: Arc<HealthState>,
    metrics_path: String,
    bind_all: bool,
) -> std::io::Result<()> {
    serve_metrics_with_cancel(addr, metrics, health, metrics_path, bind_all, None).await
}

/// Spawn the metrics HTTP service. If a cancellation token is provided, the
/// accept loop returns when the token fires.
///
/// `bind_all` must be `true` to bind a non-loopback address.
pub async fn serve_metrics_with_cancel(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    health: Arc<HealthState>,
    metrics_path: String,
    bind_all: bool,
    cancel: Option<tokio_util::sync::CancellationToken>,
) -> std::io::Result<()> {
    check_bind_policy(addr, bind_all)?;
    let listener = TcpListener::bind(addr).await?;
    serve_metrics_on_listener(listener, metrics, health, metrics_path, cancel).await
}

/// Run the metrics HTTP service on a pre-bound listener. Used by the per-core
/// server `main()` after pre-binding the metrics socket with SO_REUSEPORT
/// alongside the tunnel listeners — see `streamsockets_server::run_worker`.
pub async fn serve_metrics_on_listener(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: Arc<HealthState>,
    metrics_path: String,
    cancel: Option<tokio_util::sync::CancellationToken>,
) -> std::io::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        info!(%addr, "metrics service listening");
    }
    // /readyz must flip *only* once the tunnel accept loop is up (per
    // MIGRATION.md §9.3). The server's `run()` calls `health.mark_ready()`
    // after `build_listener()` succeeds; this function deliberately does
    // not mark ready here — clients hitting /readyz before the tunnel
    // listener binds correctly receive 503.
    let scrape_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SCRAPES));
    loop {
        // Acquire a permit BEFORE accept so the kernel queues backpressure
        // instead of us spawning unbounded handler tasks under a buggy scraper.
        let permit = match scrape_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // semaphore closed = shutting down
        };
        let accept_fut = listener.accept();
        let (stream, _peer) = match (cancel.as_ref(), accept_fut) {
            (Some(tok), fut) => {
                tokio::select! {
                    _ = tok.cancelled() => {
                        info!("metrics service cancelled; exiting accept loop");
                        return Ok(());
                    }
                    res = fut => match res {
                        Ok(s) => s,
                        Err(e) => { warn!("metrics accept error: {e}"); continue; }
                    }
                }
            }
            (None, fut) => match fut.await {
                Ok(s) => s,
                Err(e) => {
                    warn!("metrics accept error: {e}");
                    continue;
                }
            },
        };
        let metrics = metrics.clone();
        let health = health.clone();
        let path_cfg = metrics_path.clone();
        tokio::spawn(async move {
            let _permit = permit; // hold for connection lifetime
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let metrics = metrics.clone();
                let health = health.clone();
                let path_cfg = path_cfg.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(req, metrics, health, path_cfg)) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .keep_alive(false)
                .serve_connection(io, svc);
            match tokio::time::timeout(PER_CONN_DEADLINE, conn).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if !is_normal_close(&e) {
                        warn!("metrics conn error: {e}");
                    } else {
                        debug!("metrics conn closed: {e}");
                    }
                }
                Err(_) => {
                    debug!("metrics conn exceeded {:?}; dropping", PER_CONN_DEADLINE);
                }
            }
        });
    }
}

fn is_normal_close(e: &hyper::Error) -> bool {
    if e.is_incomplete_message() {
        return true;
    }
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            );
        }
        src = std::error::Error::source(s);
    }
    false
}

fn handle(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
    health: Arc<HealthState>,
    metrics_path: String,
) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    if path == metrics_path {
        // `encode_text()` can fail (poisoned mutex, encoder error). The
        // previous `unwrap_or_default()` returned an empty 200 body, which
        // Prometheus parses as "all metrics absent" — a scrape rule alerting
        // on `absent()` would silently miss the failure. Translate to 500.
        match metrics.encode_text() {
            Ok(body) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(body)))
                .expect("static response builder"),
            Err(e) => {
                warn!("metrics encode_text failed: {e}");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from_static(b"metrics encode failed\n")))
                    .expect("static response builder")
            }
        }
    } else if path == "/healthz" {
        if health.is_draining() {
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from_static(b"draining")))
                .expect("static response builder")
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(b"OK")))
                .expect("static response builder")
        }
    } else if path == "/livez" {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"OK")))
            .expect("static response builder")
    } else if path == "/readyz" {
        if health.is_ready() && !health.is_draining() {
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(b"OK")))
                .expect("static response builder")
        } else {
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from_static(b"not ready")))
                .expect("static response builder")
        }
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .expect("static response builder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touch every counter/gauge so it appears in TextEncoder output, then
    /// assert ALL_METRIC_NAMES is fully covered.
    #[test]
    fn registry_renders_every_spec_metric() {
        let m = Metrics::new();

        // Preserved (§9.1)
        m.record_connection_start("alice");
        m.record_bytes_received("alice", 100);
        m.record_bytes_sent("alice", 200);
        m.record_connection_end("alice", 1.0);

        // New (§9.2)
        m.handshake_failures.with_label_values(&["auth"]).inc();
        m.handshake_version.with_label_values(&["v2"]).set(1.0);
        m.handshake_timeouts.inc();
        m.tls_handshake_failures
            .with_label_values(&["bad_cert"])
            .inc();
        m.reconnect_attempts.with_label_values(&["alice"]).inc();
        m.reconnect_state.with_label_values(&["alice"]).set(0.0);
        m.ping_timeouts.with_label_values(&["alice"]).inc();
        m.ping_rtt_seconds
            .with_label_values(&["alice"])
            .observe(0.012);
        m.ws_close.with_label_values(&["server", "1000"]).inc();
        m.protocol_violations
            .with_label_values(&["text_frame"])
            .inc();
        m.upstream_dns_failures.inc();
        m.upstream_connect_failures.inc();
        m.upstream_unreachable.inc();
        m.upstream_send_drops.inc();
        m.downstream_queue_drops.inc();
        m.upstream_truncated.inc();
        m.queue_depth_bytes.with_label_values(&["alice"]).set(0.0);
        m.queue_dropped
            .with_label_values(&["alice", "overflow"])
            .inc();
        m.queue_purged.with_label_values(&["alice"]).inc();
        m.client_foreign_sources.inc();
        m.active_tunnels.set(0.0);
        m.udp_egress_socket_buffer_bytes
            .with_label_values(&["recv"])
            .set(4_194_304.0);
        m.runtime_kind.with_label_values(&["tokio"]).set(1.0);
        m.client_state.with_label_values(&["live"]).set(1.0);

        // §13.3 row 13
        m.udp_idle_closes.inc();

        let text = String::from_utf8(m.encode_text().expect("encode")).unwrap();
        for name in ALL_METRIC_NAMES {
            assert!(text.contains(name), "missing metric: {name}");
        }

        // Verify exact count is in lockstep with spec — guards against silent
        // additions that aren't reflected in MIGRATION.md.
        // 6 (§9.1 preserved) + 24 (§9.2 new — incl. upstream_truncated_total and
        //                          downstream_queue_drops_total added in v2.0.0) +
        // 1 (§13.3 udp_idle_closes_total)
        // = 31.
        assert_eq!(
            ALL_METRIC_NAMES.len(),
            31,
            "ALL_METRIC_NAMES count drifted from spec (6 preserved + 24 new + udp_idle_closes_total)"
        );
    }

    /// Every documented `handshake_failures_total{reason}` value renders.
    #[test]
    fn handshake_reasons_distinct_labels() {
        let m = Metrics::new();
        for r in [
            "auth",
            "ip_denied",
            "route_denied",
            "reuse_conflict",
            "capacity",
            "bad_request",
        ] {
            m.handshake_failures.with_label_values(&[r]).inc();
        }
        let text = String::from_utf8(m.encode_text().expect("encode")).unwrap();
        for r in [
            "auth",
            "ip_denied",
            "route_denied",
            "reuse_conflict",
            "capacity",
            "bad_request",
        ] {
            assert!(
                text.contains(&format!("reason=\"{r}\"")),
                "missing reason label `{r}` in encoded text"
            );
        }
    }

    /// `ws_close_total{side}` accepts both `client` and `server` (per §13.3
    /// rows 11/12 — the SHIP-BLOCKER from VERDICT.md was that the server
    /// always emitted `server` for received closes; the metric itself supports
    /// both).
    #[test]
    fn ws_close_accepts_both_sides() {
        let m = Metrics::new();
        m.ws_close.with_label_values(&["server", "1000"]).inc();
        m.ws_close.with_label_values(&["client", "1000"]).inc();
        let text = String::from_utf8(m.encode_text().expect("encode")).unwrap();
        assert!(text.contains("side=\"server\""));
        assert!(text.contains("side=\"client\""));
    }

    /// Histograms expose the spec'd buckets.
    #[test]
    fn connection_duration_buckets_match_spec() {
        let m = Metrics::new();
        m.record_connection_start("a");
        m.record_connection_end("a", 7.0);
        let text = String::from_utf8(m.encode_text().expect("encode")).unwrap();
        // Spec §9.1: buckets 1, 5, 10, 30, 60, 300, 600, 1800, 3600
        for b in ["1", "5", "10", "30", "60", "300", "600", "1800", "3600"] {
            let needle = format!("le=\"{b}\"");
            assert!(text.contains(&needle), "missing bucket le={b}");
        }
    }

    /// `runtime_kind` accepts the three spec'd labels: io_uring, epoll, tokio.
    #[test]
    fn runtime_kind_accepts_three_labels() {
        let m = Metrics::new();
        for k in ["io_uring", "epoll", "tokio"] {
            m.runtime_kind.with_label_values(&[k]).set(1.0);
        }
        let text = String::from_utf8(m.encode_text().expect("encode")).unwrap();
        for k in ["io_uring", "epoll", "tokio"] {
            assert!(text.contains(&format!("kind=\"{k}\"")), "missing kind={k}");
        }
    }

    /// /readyz must remain 503 until `mark_ready()` is called. Health state
    /// behavior is the contract; the HTTP wiring is exercised in the server's
    /// integration suite.
    #[test]
    fn health_state_initially_not_ready_or_draining() {
        let h = HealthState::new();
        assert!(!h.is_ready());
        assert!(!h.is_draining());
        h.mark_ready();
        assert!(h.is_ready());
        h.mark_draining();
        assert!(h.is_draining());
    }
}
