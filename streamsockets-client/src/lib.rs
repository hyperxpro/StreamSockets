//! streamsockets-client v2.
//!
//! FSM, reconnect, lock-on, and queue semantics are documented at the call
//! sites in `fsm.rs`, `ws.rs`, and `queue.rs`.
#![deny(clippy::await_holding_lock)]
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
    clippy::ignored_unit_patterns,
    clippy::single_match,
    clippy::bool_to_int_with_if,
    clippy::needless_bool,
    clippy::ptr_as_ptr,
    clippy::ref_as_ptr,
    clippy::borrow_as_ptr,
    clippy::redundant_else,
    clippy::unnecessary_literal_bound,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::large_stack_arrays,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::used_underscore_binding,
    clippy::unused_self,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::trivially_copy_pass_by_ref,
    clippy::wildcard_imports,
    clippy::format_push_string,
    clippy::uninlined_format_args
)]

pub mod backoff;
pub mod fsm;
pub mod queue;
pub mod ws;

use std::path::PathBuf;
use std::time::Duration;

use streamsockets_core::{env_bool, env_value, env_value_as_int, env_value_as_u64};

/// String wrapper whose `Debug` prints `<redacted>` instead of bytes. Cheap
/// (`Clone` is `String::clone`); deliberately does NOT zero memory on drop —
/// for that level of paranoia an operator should set `MEMORY_DENY_WRITE_EXECUTE`
/// + page-locked allocator and bring in `zeroize`. The goal here is preventing
/// accidental log leak via `tracing::info!(?cfg, ...)`.
#[derive(Clone)]
pub struct RedactedString(String);

impl RedactedString {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl PartialEq for RedactedString {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let a = self.0.as_bytes();
        let b = other.0.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

impl Eq for RedactedString {}

impl From<String> for RedactedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RedactedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}
use tracing::{info, warn};

/// Per-process client configuration. `auth_token` is wrapped in `SecretString`
/// so its bytes never appear in `Debug` output (defense against future
/// `tracing::info!(?cfg, ...)` logging by maintainers).
#[derive(Clone)]
pub struct ClientConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub websocket_uri: String,
    pub auth_token: RedactedString,
    pub route: String, // host:port (IPv6 brackets stripped — see route_address())
    pub ping_interval_ms: u64,
    pub ping_timeout_ms: u64,
    pub ping_permitted_misses: u32,
    pub retry_initial_delay_ms: u64,
    pub retry_max_delay_ms: u64,
    pub retry_budget: u32,
    pub udp_timeout_secs: u64,
    pub exit_on_failure: bool,
    pub queue_max_bytes: u64,
    /// Maximum number of frames buffered for replay on reconnect. FIFO with
    /// drop-oldest. Operates alongside `queue_max_bytes`; whichever cap is
    /// hit first triggers eviction. Set to 0 to disable the queue (every
    /// frame written while disconnected is dropped immediately).
    pub queue_max_packets: usize,
    pub queue_drain_timeout_ms: u64,
    pub threads: u32,
    pub max_frame_size: usize,
    /// Inflight UDP-listener channel cap (frames). Per-frame size bounded by
    /// `max_frame_size`; total in-flight memory ≤ `udp_channel_capacity * max_frame_size`.
    pub udp_channel_capacity: usize,
    /// Per-process opt-out for the ws:// + AUTH_TOKEN startup refusal.
    /// Set `ALLOW_INSECURE_AUTH=true` to allow plaintext token transmission.
    pub allow_insecure_auth: bool,
    /// Per-process opt-out for the empty-AUTH_TOKEN startup refusal.
    /// Set `ALLOW_NO_AUTH=true` to run without an auth token.
    pub allow_no_auth: bool,
    /// Currently unused. Root store is loaded from the OS via
    /// `rustls-platform-verifier`. Retained as an explicit `None` so
    /// downstream consumers (testsuite) can construct `ClientConfig`
    /// literally; wiring a PEM file as additional roots is a future change.
    #[allow(dead_code)]
    pub tls_ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("bind_address", &self.bind_address)
            .field("bind_port", &self.bind_port)
            .field("websocket_uri", &self.websocket_uri)
            .field("auth_token", &"<redacted>")
            .field("route", &self.route)
            .field("ping_interval_ms", &self.ping_interval_ms)
            .field("ping_timeout_ms", &self.ping_timeout_ms)
            .field("ping_permitted_misses", &self.ping_permitted_misses)
            .field("retry_initial_delay_ms", &self.retry_initial_delay_ms)
            .field("retry_max_delay_ms", &self.retry_max_delay_ms)
            .field("retry_budget", &self.retry_budget)
            .field("udp_timeout_secs", &self.udp_timeout_secs)
            .field("exit_on_failure", &self.exit_on_failure)
            .field("queue_max_bytes", &self.queue_max_bytes)
            .field("queue_max_packets", &self.queue_max_packets)
            .field("queue_drain_timeout_ms", &self.queue_drain_timeout_ms)
            .field("threads", &self.threads)
            .field("max_frame_size", &self.max_frame_size)
            .field("udp_channel_capacity", &self.udp_channel_capacity)
            .field("allow_insecure_auth", &self.allow_insecure_auth)
            .field("allow_no_auth", &self.allow_no_auth)
            .field("tls_ca_file", &self.tls_ca_file)
            .finish()
    }
}

impl ClientConfig {
    pub fn from_env() -> Self {
        let cores = streamsockets_core::num_cores();
        let default_threads: u32 = if cfg!(target_os = "linux") {
            (cores as u32).max(1) * 2
        } else {
            1
        };

        let retry_initial_secs = env_value_as_u64("RETRY_INITIAL_DELAY_SECONDS", 1);
        // Migration: clamp at 100ms floor unless RETRY_INITIAL_DELAY_SECONDS >= 1.
        let retry_initial_ms = if retry_initial_secs == 0 {
            100
        } else {
            retry_initial_secs * 1000
        };

        Self {
            bind_address: env_value("BIND_ADDRESS", "0.0.0.0"),
            bind_port: env_value_as_int("BIND_PORT", 9000) as u16,
            websocket_uri: env_value("WEBSOCKET_URI", "ws://localhost:8080/tunnel"),
            auth_token: RedactedString::new(env_value("AUTH_TOKEN", "")),
            route: env_value("ROUTE", "127.0.0.1:8888"),
            ping_interval_ms: env_value_as_u64("PING_INTERVAL_MILLIS", 5000),
            ping_timeout_ms: env_value_as_u64("PING_TIMEOUT_MILLIS", 10_000),
            ping_permitted_misses: env_value_as_int("PING_PERMITTED_MISSES", 1) as u32,
            retry_initial_delay_ms: retry_initial_ms,
            retry_max_delay_ms: env_value_as_u64("RETRY_MAX_DELAY_SECONDS", 30) * 1000,
            retry_budget: env_value_as_int("RETRY_BUDGET", 100) as u32,
            udp_timeout_secs: env_value_as_u64("UDP_TIMEOUT", 300),
            exit_on_failure: env_bool("EXIT_ON_FAILURE", false),
            queue_max_bytes: env_value_as_u64("QUEUE_MAX_BYTES", 1_048_576),
            queue_max_packets: env_value_as_int("QUEUE_MAX_PACKETS", 32) as usize,
            queue_drain_timeout_ms: env_value_as_u64("QUEUE_DRAIN_TIMEOUT_MS", 30_000),
            threads: env_value_as_int("THREADS", default_threads as i64) as u32,
            max_frame_size: env_value_as_int("MAX_FRAME_SIZE", 65536) as usize,
            udp_channel_capacity: env_value_as_int("UDP_CHANNEL_CAPACITY", 1024) as usize,
            allow_insecure_auth: env_bool("ALLOW_INSECURE_AUTH", false),
            allow_no_auth: env_bool("ALLOW_NO_AUTH", false),
            tls_ca_file: None,
        }
    }

    /// Validate operator-provided configuration. Returns an error describing
    /// the first invariant violation. Called from `main.rs` *before* worker
    /// spawn so misconfiguration fails fast at startup, not on first dial.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // (Fix #9) THREADS bound.
        if self.threads == 0 {
            return Err(ConfigError::Invalid("THREADS must be >= 1".into()));
        }
        if self.threads > 256 {
            return Err(ConfigError::Invalid(format!(
                "THREADS={} exceeds cap of 256",
                self.threads
            )));
        }
        // (Fix #10) MAX_FRAME_SIZE bound: Ethernet MTU floor, u16 ceiling.
        if self.max_frame_size < 1500 {
            return Err(ConfigError::Invalid(format!(
                "MAX_FRAME_SIZE={} below Ethernet MTU floor (1500)",
                self.max_frame_size
            )));
        }
        if self.max_frame_size > 65536 {
            return Err(ConfigError::Invalid(format!(
                "MAX_FRAME_SIZE={} exceeds documented ceiling (65536)",
                self.max_frame_size
            )));
        }
        // (Fix #7) Strict ROUTE parser.
        let (_, route_port) = parse_route_strict(&self.route)
            .ok_or_else(|| ConfigError::Invalid(format!("invalid ROUTE: {}", self.route)))?;
        if route_port == 0 {
            return Err(ConfigError::Invalid("ROUTE port must be non-zero".into()));
        }
        // Parse the websocket URI once for the remaining checks.
        let url = url::Url::parse(&self.websocket_uri)
            .map_err(|e| ConfigError::Invalid(format!("invalid WEBSOCKET_URI: {e}")))?;
        let scheme = url.scheme();
        let use_tls = match scheme {
            "ws" => false,
            "wss" => true,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "unsupported WEBSOCKET_URI scheme: {other}"
                )));
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| ConfigError::Invalid("WEBSOCKET_URI missing host".into()))?;
        // (Fix #17) :0 is never valid for an outbound dial.
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ConfigError::Invalid("WEBSOCKET_URI missing port".into()))?;
        if port == 0 {
            return Err(ConfigError::Invalid(
                "WEBSOCKET_URI port must be non-zero".into(),
            ));
        }
        // (Fix #14) wss:// to a literal IP — `url` strips brackets from
        // host_str so detect via parse::<IpAddr>(). The TLS handshake
        // will use ServerName::IpAddress; this only validates the host
        // is something the rustls verifier can consume.
        if use_tls {
            // ServerName::try_from already accepts an IP literal, but bracket
            // forms like "[::1]" would slip through `url` only if a future
            // url-crate change stops stripping; reject defensively.
            if host.starts_with('[') || host.ends_with(']') {
                return Err(ConfigError::Invalid(format!(
                    "WEBSOCKET_URI host {host:?} contains brackets after URL parse"
                )));
            }
        }
        // (Fix #1) Plaintext token over ws:// — refuse unless explicit opt-out.
        if !use_tls && !self.auth_token.is_empty() && !self.allow_insecure_auth {
            return Err(ConfigError::InsecureScheme);
        }
        // (Fix #8) Empty token — refuse unless explicit opt-out.
        if self.auth_token.is_empty() && !self.allow_no_auth {
            return Err(ConfigError::MissingAuthToken);
        }
        Ok(())
    }

    /// Returns the route's host portion. Strips IPv6 brackets so the result is
    /// directly usable as `IpAddr` parse input or DNS lookup input.
    pub fn route_address(&self) -> &str {
        let (addr, _) = parse_route(&self.route).unwrap_or((self.route.as_str(), 0));
        addr
    }
    pub fn route_port(&self) -> u16 {
        parse_route(&self.route).map(|(_, p)| p).unwrap_or(0)
    }
    pub fn auth_token_str(&self) -> &str {
        self.auth_token.expose()
    }
    pub fn retry_initial(&self) -> Duration {
        Duration::from_millis(self.retry_initial_delay_ms)
    }
    pub fn retry_max(&self) -> Duration {
        Duration::from_millis(self.retry_max_delay_ms)
    }
    pub fn ping_interval(&self) -> Duration {
        Duration::from_millis(self.ping_interval_ms)
    }
    pub fn ping_timeout(&self) -> Duration {
        Duration::from_millis(self.ping_timeout_ms)
    }
    pub fn udp_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_timeout_secs)
    }
    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.queue_drain_timeout_ms)
    }
}

/// Configuration validation errors surfaced at startup before any worker spawns.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "WEBSOCKET_URI is ws:// (plaintext) but AUTH_TOKEN is non-empty; refusing to send the token in cleartext. \
         Either switch to wss:// or set ALLOW_INSECURE_AUTH=true to acknowledge the risk."
    )]
    InsecureScheme,
    #[error(
        "AUTH_TOKEN is empty; refusing to start. Set AUTH_TOKEN=<token> or set ALLOW_NO_AUTH=true to opt out."
    )]
    MissingAuthToken,
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Strict ROUTE parser. Accepts:
///   - `host:port` where host has no embedded `:` (IPv4 literal or DNS name)
///   - `[ipv6-literal]:port`
/// Rejects unbracketed IPv6 literals such as `::1:8888`, which the previous
/// `rsplit_once(':')` parser silently corrupted: `("::1", 8888)` looks like an
/// IPv6 host but the kernel routing path treats `::1` as a v6 address while
/// the actual operator intent could have been `[::1]:8888` *or* a typo of a
/// hostname. Refuse the ambiguity.
pub fn parse_route(s: &str) -> Option<(&str, u16)> {
    parse_route_strict(s)
}

fn parse_route_strict(s: &str) -> Option<(&str, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]:8888`.
        let (addr, tail) = rest.split_once(']')?;
        let port_str = tail.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        // Verify the bracketed body is a real IPv6 literal.
        addr.parse::<std::net::Ipv6Addr>().ok()?;
        return Some((addr, port));
    }
    // Unbracketed: at most one `:` allowed (IPv4 literal or DNS name).
    if s.matches(':').count() > 1 {
        return None;
    }
    let (addr, port_str) = s.rsplit_once(':')?;
    if addr.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    Some((addr, port))
}

/// Build a UDP listener with SO_REUSEPORT (Linux/BSD) and SO_REUSEADDR set,
/// returning a `std::net::UdpSocket`. The caller converts to a tokio
/// `UdpSocket` inside its own per-core runtime via `UdpSocket::from_std`.
///
/// Pre-binding all N UDP sockets with SO_REUSEPORT *before* any worker calls
/// `recv_from()` guarantees the kernel's UDP-fanout hash sees the full group
/// from the first datagram (matches the Java `client/UdpServer.java` model).
pub fn build_listener_udp_std(bind: std::net::SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
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
    Ok(sock.into())
}

/// Install SIGTERM/SIGINT handler. First signal cancels `shutdown`, allowing
/// the FSM to send WS Close 1001 cleanly. Second signal forces immediate exit.
/// Called from worker-0 only — the shared `CancellationToken` broadcasts to
/// every per-core worker.
#[cfg(unix)]
pub fn spawn_signal_handler(shutdown: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("install SIGTERM: {e}");
                return;
            }
        };
        let mut intr = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                warn!("install SIGINT: {e}");
                return;
            }
        };
        let mut signals = 0u32;
        loop {
            tokio::select! {
                _ = term.recv() => {}
                _ = intr.recv() => {}
            }
            signals += 1;
            if signals == 1 {
                info!("received signal; initiating graceful shutdown");
                shutdown.cancel();
            } else {
                warn!("second signal; force-exiting");
                std::process::exit(143);
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_signal_handler(shutdown: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("received Ctrl+C; initiating graceful shutdown");
            shutdown.cancel();
        }
    });
}

/// Initialize per-process state used by every worker: log startup, warn on
/// removed/deprecated env vars, set the `runtime_kind` metric.
pub fn init_shared(cfg: &ClientConfig) {
    info!(
        bind = %format!("{}:{}", cfg.bind_address, cfg.bind_port),
        ws = %cfg.websocket_uri,
        route = %cfg.route,
        exit_on_failure = cfg.exit_on_failure,
        "starting streamsockets-client v2.2.0"
    );

    // Warn-and-ignore the v1 env var that v2 no longer honors.
    if std::env::var_os("USE_OLD_PROTOCOL").is_some() {
        warn!("USE_OLD_PROTOCOL is set but ignored — v2 client only speaks v2");
    }
    if cfg.allow_insecure_auth {
        warn!(
            "ALLOW_INSECURE_AUTH=true: bearer credentials will be sent in cleartext \
             over ws://. Use wss:// in production."
        );
    }
    if cfg.allow_no_auth && cfg.auth_token.is_empty() {
        warn!("ALLOW_NO_AUTH=true: starting client without an auth credential");
    }

    if cfg.client_ip_header_warning_applies() {
        warn!(
            "the upstream server uses CLIENT_IP_HEADER trust without CIDR allowlist. \
             Ensure your network restricts direct access to the WS endpoint or that all \
             traffic transits a trusted L4/L7 proxy that strips/sets the header."
        );
    }

    // (§3.3) MAX_FRAME_SIZE mismatch warning: if the client's cap is below the
    // v2 default 65536 and the server's cap is larger, server-emitted frames
    // in the gap trip `WebSocketError::FrameTooLarge` on the client and
    // surface as a spurious close code 1002. Match client and server.
    if cfg.max_frame_size < 65536 {
        warn!(
            max_frame_size = cfg.max_frame_size,
            "MAX_FRAME_SIZE is below the v2 default (65536). If the SERVER's \
             MAX_FRAME_SIZE is larger, server-emitted frames in the gap will \
             trip WebSocketError::FrameTooLarge on the client and surface as a \
             spurious close code 1002. Match client and server."
        );
    }

    // (§10.2.4) Unbounded packet queues defeat the point of the cap. Warn
    // loudly so an operator who set QUEUE_MAX_PACKETS=1_000_000 notices.
    if cfg.queue_max_packets > 10_000 {
        warn!(
            queue_max_packets = cfg.queue_max_packets,
            "QUEUE_MAX_PACKETS is unusually large (>10_000). The replay set is \
             unlikely to be useful at this depth — stale UDP is typically \
             discarded by the application. Consider lowering."
        );
    }

    let metrics = streamsockets_metrics::Metrics::global();
    let runtime_kind = streamsockets_core::pick_runtime();
    metrics
        .runtime_kind
        .with_label_values(&[runtime_kind.label()])
        .set(1.0);
}

impl ClientConfig {
    /// Whether to emit a startup warning about CLIENT_IP_HEADER spoofability.
    /// Currently always emits when the operator sets the upstream-server-side
    /// env that documents header trust. Conservative — better-safe-than-sorry.
    fn client_ip_header_warning_applies(&self) -> bool {
        std::env::var_os("CLIENT_IP_HEADER_WARNING_DISABLE").is_none()
            && std::env::var_os("CLIENT_IP_HEADER").is_some()
    }
}
