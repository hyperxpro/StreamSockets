//! streamsockets-server: HTTP/WS handshake → header auth → upstream UDP forwarder.
//!
//! Wire protocol, data flow, and graceful-drain semantics are documented at
//! the call sites in `handshake.rs`, `tunnel.rs`, and `run()` below.

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
    clippy::uninlined_format_args,
    clippy::unused_async
)]

pub mod handshake;
pub mod proxy_protocol;
pub mod tls;
pub mod tunnel;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use parking_lot::Mutex as PlMutex;
use streamsockets_auth::TokenAuthentication;
use streamsockets_core::{env_bool, env_opt, env_value, env_value_as_int, env_value_as_u64};
use streamsockets_metrics::{HealthState, Metrics};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub ws_path: String,
    pub max_frame_size: usize,
    pub http_max_content_length: usize,
    pub accounts_file: PathBuf,
    pub reload_interval_seconds: u64,
    pub metrics_enabled: bool,
    pub metrics_bind_address: String,
    pub metrics_port: u16,
    pub metrics_path: String,
    pub max_concurrent_connections: u64,
    /// Per-source-IP concurrent connection cap. 0 disables. Defends against a
    /// single attacker filling the global capacity with half-open handshakes.
    pub per_ip_max_concurrent: u32,
    pub shutdown_grace_seconds: u64,
    pub client_ip_header: Option<String>,
    /// CIDR allowlist of trusted L4/L7 proxies. When non-empty, `CLIENT_IP_HEADER`
    /// is honored ONLY for connections whose direct peer IP falls in one of these
    /// CIDRs. When empty AND `client_ip_header` is set, server fails to start —
    /// the previous "warn and trust" behavior was an auth bypass.
    pub client_ip_header_trusted_cidrs: Vec<ipnet::IpNet>,
    pub proxy_protocol: ProxyProtocolMode,
    /// CIDR allowlist of TCP peers permitted to send a PROXY-protocol header.
    /// REQUIRED whenever `proxy_protocol != Disabled`. Without this, any
    /// reachable peer can spoof the client source IP via a forged PROXY header.
    pub proxy_protocol_trusted_cidrs: Vec<ipnet::IpNet>,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
    pub tls_require_client_cert: bool,
    pub tls_client_ca_file: Option<PathBuf>,
    /// When true, allow the metrics endpoint to bind to a wildcard address
    /// (`0.0.0.0` / `::`). Default false — production binds typically should be
    /// loopback or a private interface to avoid exposing the registry.
    pub metrics_bind_all: bool,
    /// `listen(2)` backlog passed to the tunnel + metrics sockets. Default 4096.
    /// Tune up under SYN-flood scenarios; the kernel caps this at
    /// `net.core.somaxconn`.
    pub listen_backlog: i32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyProtocolMode {
    Disabled,
    V1,
    V2,
    Optional,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        let proxy_protocol = match env_value("PROXY_PROTOCOL", "disabled").as_str() {
            "v1" => ProxyProtocolMode::V1,
            "v2" => ProxyProtocolMode::V2,
            "optional" => ProxyProtocolMode::Optional,
            _ => ProxyProtocolMode::Disabled,
        };
        Self {
            bind_address: env_value("BIND_ADDRESS", "0.0.0.0"),
            bind_port: env_value_as_int("BIND_PORT", 8080) as u16,
            ws_path: env_value("WS_PATH", "/tunnel"),
            max_frame_size: env_value_as_int("MAX_FRAME_SIZE", 65536) as usize,
            http_max_content_length: env_value_as_int("HTTP_MAX_CONTENT_LENGTH", 65536) as usize,
            accounts_file: PathBuf::from(env_value("ACCOUNTS_CONFIG_FILE", "accounts.yaml")),
            reload_interval_seconds: env_value_as_u64("ACCOUNTS_RELOAD_INTERVAL_SECONDS", 15),
            metrics_enabled: env_bool("METRICS_ENABLED", true),
            metrics_bind_address: env_value("METRICS_BIND_ADDRESS", "0.0.0.0"),
            metrics_port: env_value_as_int("METRICS_PORT", 9090) as u16,
            metrics_path: env_value("METRICS_PATH", "/metrics"),
            max_concurrent_connections: env_value_as_u64("MAX_CONCURRENT_CONNECTIONS", 100_000),
            per_ip_max_concurrent: env_value_as_int("PER_IP_MAX_CONCURRENT", 256) as u32,
            shutdown_grace_seconds: env_value_as_u64("SHUTDOWN_GRACE_SECONDS", 30),
            client_ip_header: env_opt("CLIENT_IP_HEADER"),
            client_ip_header_trusted_cidrs: parse_trusted_cidrs(
                env_opt("CLIENT_IP_HEADER_TRUSTED_CIDRS").as_deref(),
            )
            .unwrap_or_else(|e| {
                panic!("CLIENT_IP_HEADER_TRUSTED_CIDRS: {e}");
            }),
            proxy_protocol,
            proxy_protocol_trusted_cidrs: parse_trusted_cidrs(
                env_opt("PROXY_PROTOCOL_TRUSTED_CIDRS").as_deref(),
            )
            .unwrap_or_else(|e| {
                panic!("PROXY_PROTOCOL_TRUSTED_CIDRS: {e}");
            }),
            tls_cert_file: env_opt("TLS_CERT_FILE").map(PathBuf::from),
            tls_key_file: env_opt("TLS_KEY_FILE").map(PathBuf::from),
            tls_require_client_cert: env_bool("TLS_REQUIRE_CLIENT_CERT", false),
            tls_client_ca_file: env_opt("TLS_CLIENT_CA_FILE").map(PathBuf::from),
            metrics_bind_all: env_bool("METRICS_BIND_ALL", false),
            listen_backlog: env_value_as_int("LISTEN_BACKLOG", 4096) as i32,
        }
    }
}

/// Parse a comma-separated list of CIDR allowlist entries (used for both
/// `CLIENT_IP_HEADER_TRUSTED_CIDRS` and `PROXY_PROTOCOL_TRUSTED_CIDRS`).
/// Returns Err on the first invalid entry — silently skipping was a footgun:
/// a typo like `10.0.0.0/33` would shrink the allowlist to nothing while the
/// caller's "non-empty?" check still passed if other entries were valid.
fn parse_trusted_cidrs(s: Option<&str>) -> Result<Vec<ipnet::IpNet>, String> {
    let Some(s) = s else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for raw in s.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        match raw.parse::<ipnet::IpNet>() {
            Ok(net) => out.push(net),
            Err(e) => return Err(format!("invalid CIDR `{raw}`: {e}")),
        }
    }
    Ok(out)
}

pub struct Server {
    pub cfg: Arc<ServerConfig>,
    pub auth: Arc<TokenAuthentication>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthState>,
    /// Top-level graceful-shutdown token (first SIGTERM). Tunnels send WS Close 1001
    /// and drain for `SHUTDOWN_GRACE_SECONDS`.
    pub shutdown: CancellationToken,
    /// Force-close token (second SIGTERM). Tunnels skip the grace window and send
    /// WS Close 1012 ("Service Restart") immediately, with UDP egress closed last.
    pub force_close: CancellationToken,
    /// SIGHUP-driven reload signal. Each `notify_one()` triggers one wakeup of
    /// every subscribed watcher (cert reload, etc.).
    pub reload: Arc<Notify>,
    pub tls: Option<tls::TlsAcceptor>,
    /// Hot-reloadable cert resolver (None when TLS is disabled). SIGHUP triggers
    /// `reload()` so cert rotation does not require a process restart.
    pub tls_resolver: Option<Arc<tls::HotReloadResolver>>,
    pub active_count: Arc<std::sync::atomic::AtomicU64>,
    /// Per-source-IP active connection counters. Entries are removed on drop
    /// of the last `PerIpGuard` so the map cannot grow unbounded. Backed by
    /// `parking_lot::Mutex` so `Drop` can decrement synchronously without
    /// spawning onto the runtime — the previous `tokio::spawn` in Drop
    /// panicked during runtime tear-down. The critical section is one
    /// HashMap probe (O(1), uncontended in practice).
    pub per_ip: Arc<PlMutex<HashMap<std::net::IpAddr, u32>>>,
}

/// RAII guard that decrements (and eventually removes) the per-IP counter on drop.
/// Acquired by `try_acquire_per_ip` after a successful capacity check.
pub struct PerIpGuard {
    map: Arc<PlMutex<HashMap<std::net::IpAddr, u32>>>,
    ip: std::net::IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        // Synchronous decrement: parking_lot mutex, single hash probe. Safe to
        // run during runtime tear-down (no `tokio::spawn`).
        let mut g = self.map.lock();
        if let Some(c) = g.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                g.remove(&self.ip);
            }
        }
    }
}

/// Aggregate an IPv6 address into a /64-prefixed key for the per-IP cap.
/// IPv6 hosts typically hold an entire /64; without aggregation an attacker
/// rotates source addresses within their delegation and bypasses the cap.
/// IPv4 addresses are returned unchanged.
fn per_ip_cap_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(_) => ip,
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            // Mask to /64: keep the first 4 segments, zero the rest.
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0,
            ))
        }
    }
}

/// Try to admit a new connection from `ip`. Returns `None` if the per-IP cap
/// is reached. The guard's `Drop` releases the slot. IPv6 addresses are
/// aggregated to /64 before the cap check.
pub fn try_acquire_per_ip(server: &Server, ip: std::net::IpAddr) -> Option<PerIpGuard> {
    let cap = server.cfg.per_ip_max_concurrent;
    let key = per_ip_cap_key(ip);
    if cap == 0 {
        // Disabled — return a no-op guard that points at an empty map.
        return Some(PerIpGuard {
            map: server.per_ip.clone(),
            ip: key,
        });
    }
    let mut g = server.per_ip.lock();
    let cur = g.entry(key).or_insert(0);
    if *cur >= cap {
        return None;
    }
    *cur += 1;
    Some(PerIpGuard {
        map: server.per_ip.clone(),
        ip: key,
    })
}

/// Initialize shared per-process state: load auth, set up metrics + health,
/// build the (optional) TLS acceptor, mint top-level cancellation tokens.
///
/// Called once from `main()` before workers spawn. The returned [`Server`] is
/// shared (Arc-cloned) into each per-core worker.
pub fn init_shared(cfg: Arc<ServerConfig>) -> anyhow::Result<Arc<Server>> {
    info!(
        bind = %format!("{}:{}", cfg.bind_address, cfg.bind_port),
        ws_path = %cfg.ws_path,
        "starting streamsockets-server v2.0.0"
    );

    // CRITICAL: refuse to start when CLIENT_IP_HEADER is set without a trusted
    // CIDR allowlist. The previous "warn and trust" behavior was an auth bypass
    // — any direct attacker could inject `X-Forwarded-For: <whitelisted-ip>` to
    // spoof past the IP allowlist.
    if cfg.client_ip_header.is_some() && cfg.client_ip_header_trusted_cidrs.is_empty() {
        anyhow::bail!(
            "CLIENT_IP_HEADER={:?} is set but CLIENT_IP_HEADER_TRUSTED_CIDRS is empty. \
             Refusing to start: this would let any direct attacker spoof the client IP. \
             Set CLIENT_IP_HEADER_TRUSTED_CIDRS to a comma-separated list of LB CIDRs, \
             or unset CLIENT_IP_HEADER.",
            cfg.client_ip_header.as_deref().unwrap_or("")
        );
    }

    // CRITICAL: same trap for PROXY protocol — if enabled without a peer-CIDR
    // allowlist, any reachable peer can forge a PROXY header to spoof source IP.
    if !matches!(cfg.proxy_protocol, ProxyProtocolMode::Disabled)
        && cfg.proxy_protocol_trusted_cidrs.is_empty()
    {
        anyhow::bail!(
            "PROXY_PROTOCOL={:?} is enabled but PROXY_PROTOCOL_TRUSTED_CIDRS is empty. \
             Refusing to start: this would let any direct attacker forge a PROXY header \
             to spoof the source IP. Set PROXY_PROTOCOL_TRUSTED_CIDRS to a comma-separated \
             list of LB CIDRs.",
            cfg.proxy_protocol
        );
    }

    // Default is `0.0.0.0` (wildcard) for parity with Java 1.7.0. Operators
    // concerned about exposing the registry can set
    // `METRICS_BIND_ADDRESS=127.0.0.1` or set `METRICS_BIND_ALL=false` (the
    // current default keeps it permissive). When wildcard-bound we log a warn
    // so operators see it in startup logs.
    if cfg.metrics_enabled {
        let bind = cfg.metrics_bind_address.trim();
        let wildcard = bind == "0.0.0.0" || bind == "::" || bind == "[::]" || bind.is_empty();
        if wildcard {
            tracing::warn!(
                "METRICS_BIND_ADDRESS={:?} is a wildcard; the /metrics, /healthz \
                 endpoints will be reachable on every interface. Bind to a private \
                 address if exposure to the public network is a concern.",
                bind
            );
        }
    }

    let auth = Arc::new(
        TokenAuthentication::from_file(&cfg.accounts_file).with_context(|| {
            format!(
                "failed to load accounts file {}",
                cfg.accounts_file.display()
            )
        })?,
    );

    let metrics = Metrics::global();
    let runtime_kind = streamsockets_core::pick_runtime();
    metrics
        .runtime_kind
        .with_label_values(&[runtime_kind.label()])
        .set(1.0);

    let health = Arc::new(HealthState::new());
    let shutdown = CancellationToken::new();
    let force_close = CancellationToken::new();
    let reload = Arc::new(Notify::new());

    let (tls, tls_resolver) = match (cfg.tls_cert_file.as_ref(), cfg.tls_key_file.as_ref()) {
        (Some(cert), Some(key)) => {
            let (acceptor, resolver) = tls::load_tls(
                cert,
                key,
                cfg.tls_require_client_cert,
                cfg.tls_client_ca_file.as_deref(),
            )?;
            (Some(acceptor), Some(resolver))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("TLS_CERT_FILE and TLS_KEY_FILE must be set together"),
    };

    Ok(Arc::new(Server {
        cfg,
        auth,
        metrics,
        health,
        shutdown,
        force_close,
        reload,
        tls,
        tls_resolver,
        active_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        per_ip: Arc::new(PlMutex::new(HashMap::new())),
    }))
}

/// Spawn a SIGHUP-driven TLS-cert reload watcher. Runs only on worker 0
/// (alongside the auth-reload watcher). The TLS acceptor itself is unchanged
/// — `HotReloadResolver` swaps the active cert in place for the next handshake.
fn spawn_tls_reload_watcher(server: Arc<Server>) {
    let resolver = match server.tls_resolver.clone() {
        Some(r) => r,
        None => return,
    };
    let reload = server.reload.clone();
    let shutdown = server.shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = reload.notified() => {
                    match resolver.clone().reload_async().await {
                        Ok(()) => info!("TLS certificate hot-reloaded from disk"),
                        Err(e) => warn!("TLS certificate reload failed; keeping previous: {e}"),
                    }
                }
            }
        }
    });
}

/// Per-core worker entrypoint. Runs the accept loop on the pre-bound
/// `listener`. On `worker_idx == 0`, also installs the SIGTERM/SIGINT handler,
/// the auth-reload watcher, the metrics service (using the pre-bound
/// `metrics_listener`), and the systemd watchdog heartbeat — these singletons
/// must run on exactly one worker.
///
/// The pre-bind-then-spawn pattern guarantees every worker's TCP socket is in
/// the kernel SO_REUSEPORT group before any accept() runs, so kernel
/// SYN-fanout sees all N sockets immediately.
pub async fn run_worker(
    server: Arc<Server>,
    listener: std::net::TcpListener,
    worker_idx: usize,
    metrics_listener: Option<std::net::TcpListener>,
) {
    // After sd_notify_ready, any expect() here would leave a half-functional
    // process while readyz is still green. Convert init failures to
    // mark_draining → graceful return so the worker drops out and the parent
    // process can exit cleanly.
    if let Err(e) = listener.set_nonblocking(true) {
        error!(
            worker = worker_idx,
            "set_nonblocking on tunnel listener failed: {e}"
        );
        server.health.mark_draining();
        server.shutdown.cancel();
        return;
    }
    let listener = match TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            error!(
                worker = worker_idx,
                "tokio TcpListener::from_std failed: {e}"
            );
            server.health.mark_draining();
            server.shutdown.cancel();
            return;
        }
    };

    if worker_idx == 0 {
        if let Err(e) = spawn_signal_handler(
            server.shutdown.clone(),
            server.force_close.clone(),
            server.reload.clone(),
            server.health.clone(),
        ) {
            error!("signal handler install failed post-readyz: {e}");
            server.health.mark_draining();
            server.shutdown.cancel();
            return;
        }

        if server.cfg.reload_interval_seconds > 0 {
            server.auth.spawn_reload_watcher_with_cancel(
                Duration::from_secs(server.cfg.reload_interval_seconds),
                Some(server.shutdown.clone()),
            );
        }

        spawn_tls_reload_watcher(server.clone());

        if let Some(ml) = metrics_listener {
            if let Err(e) = ml.set_nonblocking(true) {
                error!("set_nonblocking on metrics listener failed: {e}");
                server.health.mark_draining();
                server.shutdown.cancel();
                return;
            }
            match TcpListener::from_std(ml) {
                Ok(listener) => {
                    let m = server.metrics.clone();
                    let h = server.health.clone();
                    let p = server.cfg.metrics_path.clone();
                    let cancel = server.shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = streamsockets_metrics::serve_metrics_on_listener(
                            listener,
                            m,
                            h,
                            p,
                            Some(cancel),
                        )
                        .await
                        {
                            error!("metrics server error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("metrics tokio TcpListener::from_std failed: {e}");
                    server.health.mark_draining();
                    server.shutdown.cancel();
                    return;
                }
            }
        }

        streamsockets_core::spawn_watchdog_heartbeat(Duration::from_secs(10));
    }

    accept_loop(listener, server).await;
    info!(worker = worker_idx, "worker exited cleanly");
}

/// Build a TCP listener with SO_REUSEPORT (Linux/BSD) and SO_REUSEADDR set,
/// returning a `std::net::TcpListener`. The caller converts to a tokio listener
/// inside its own per-core runtime via `TcpListener::from_std`. Pre-binding all
/// N tunnel sockets with SO_REUSEPORT *before* any worker calls `accept()`
/// guarantees kernel SYN-fanout sees the full group from the first SYN.
pub fn build_tunnel_listener_std(
    bind: SocketAddr,
    backlog: i32,
) -> anyhow::Result<std::net::TcpListener> {
    let sock = socket2::Socket::new(
        if bind.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        if let Err(e) = sock.set_reuse_port(true) {
            warn!("set_reuse_port on tunnel listener failed: {e}");
        }
    }
    #[cfg(target_os = "linux")]
    {
        // TCP_DEFER_ACCEPT: kernel buffers the connection until data arrives,
        // saving an accept() round-trip for slow/zero-byte clients (HTTP probes etc).
        // socket2 doesn't expose this directly; use raw libc setsockopt.
        use std::os::fd::AsRawFd;
        let timeout: libc::c_int = 1;
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_DEFER_ACCEPT,
                std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            tracing::debug!(
                "TCP_DEFER_ACCEPT setsockopt failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    sock.bind(&bind.into())?;
    sock.listen(backlog)?;
    Ok(sock.into())
}

/// Build a TCP listener for the metrics service. `SO_REUSEADDR` is set so a
/// quick restart re-uses the bind, but `SO_REUSEPORT` is intentionally NOT
/// set: there is exactly one metrics listener per process and silent
/// load-balancing with a stray sidecar would corrupt scrape data.
pub fn build_metrics_listener_std(
    bind: SocketAddr,
    backlog: i32,
) -> anyhow::Result<std::net::TcpListener> {
    let sock = socket2::Socket::new(
        if bind.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    sock.bind(&bind.into())?;
    sock.listen(backlog)?;
    Ok(sock.into())
}

async fn accept_loop(listener: TcpListener, server: Arc<Server>) {
    let shutdown = server.shutdown.clone();
    let force_close = server.force_close.clone();
    let grace = Duration::from_secs(server.cfg.shutdown_grace_seconds);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        // Per-stream tuning. TCP_NODELAY and SO_KEEPALIVE are spec-required
                        // (§7.1). socket2 set on the *accepted* socket via from_raw_fd on Unix
                        // would require unsafe + std::os::fd; instead we use tokio's helpers
                        // and a socket2 view via socket2::SockRef for keepalive (zero-cost).
                        let _ = stream.set_nodelay(true);
                        #[cfg(unix)]
                        {
                            // SO_KEEPALIVE with sensible defaults: probe after 60s idle, every
                            // 10s, 6 retries. Catches half-open WAN connections.
                            let sref = socket2::SockRef::from(&stream);
                            let ka = socket2::TcpKeepalive::new()
                                .with_time(Duration::from_secs(60))
                                .with_interval(Duration::from_secs(10));
                            #[cfg(target_os = "linux")]
                            let ka = ka.with_retries(6);
                            let _ = sref.set_tcp_keepalive(&ka);
                        }

                        let server = server.clone();
                        tokio::spawn(async move {
                            handshake::serve_connection(server, stream, peer).await;
                        });
                    }
                    Err(e) => {
                        // Always pause briefly on accept errors so a transient
                        // condition (EMFILE/ENFILE, ECONNABORTED storm during
                        // a SYN-flood/RST-flood, EAGAIN on broken cgroups)
                        // doesn't peg a core in a tight retry loop.
                        let kind = e.raw_os_error();
                        if matches!(kind, Some(libc::EMFILE) | Some(libc::ENFILE)) {
                            server
                                .metrics
                                .protocol_violations
                                .with_label_values(&["accept_emfile"])
                                .inc();
                            warn!("accept hit FD limit ({e}); pausing 100 ms");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        } else if matches!(kind, Some(libc::ECONNABORTED)) {
                            // Routine on connection abort during SYN-flood; debug
                            // not warn to avoid log spam. Still back off briefly.
                            tracing::debug!("accept ECONNABORTED; pausing 10 ms");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        } else {
                            warn!("accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }
    }

    // After cancel: tunnels see shutdown.cancelled(), send 1001, drain for `grace`,
    // then hard-close with 1012. We wait grace+1s so the per-tunnel drain timer
    // always fires before we tear the runtime down. If `force_close` is signaled
    // (second SIGTERM), we wake immediately and let the runtime drop tunnels.
    info!(grace_secs = grace.as_secs(), "draining tunnels");
    let drain_deadline = tokio::time::Instant::now() + grace + Duration::from_secs(1);
    let metrics = server.metrics.clone();
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll.tick().await; // skip immediate fire
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(drain_deadline) => {
                info!("grace period elapsed; exiting");
                break;
            }
            _ = force_close.cancelled() => {
                warn!("second signal received; force-closing all tunnels with 1012");
                // Per-tunnel futures observe `force_close` directly and race to
                // send 1012; the previous unconditional 500 ms sleep here just
                // delayed the hard-stop signal. Drop straight through.
                break;
            }
            _ = poll.tick() => {
                if metrics.active_tunnels.get() <= 0.0 {
                    info!("all tunnels drained; exiting early");
                    break;
                }
            }
        }
    }
}

fn spawn_signal_handler(
    shutdown: CancellationToken,
    force_close: CancellationToken,
    reload: Arc<Notify>,
    health: Arc<HealthState>,
) -> std::io::Result<()> {
    // Install all three signal handlers up front. If any fail (e.g. a sandbox
    // that prohibits SIGHUP), bubble the error to the caller so it can flip
    // /healthz to draining instead of panicking post-readyz.
    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        let mut signals = 0u32;
        loop {
            tokio::select! {
                _ = hup.recv() => {
                    info!("received SIGHUP; signaling reload to subscribers");
                    reload.notify_waiters();
                    continue;
                }
                _ = term.recv() => {}
                _ = intr.recv() => {}
            }
            signals += 1;
            if signals == 1 {
                info!("received SIGTERM/SIGINT; flipping /healthz to draining");
                health.mark_draining();
                shutdown.cancel();
            } else if signals == 2 {
                warn!("second signal; force-close path engaged");
                force_close.cancel();
            } else {
                warn!("third signal; exiting hard");
                std::process::exit(143);
            }
        }
    });
    Ok(())
}
