//! streamsockets-server: HTTP/WS handshake → header auth → upstream UDP forwarder.
//!
//! See MIGRATION.md §5 (wire protocol), §7.1 (data flow), §6.7 (graceful drain).

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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use streamsockets_auth::TokenAuthentication;
use streamsockets_core::{env_bool, env_opt, env_value, env_value_as_int, env_value_as_u64};
use streamsockets_metrics::{HealthState, Metrics};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
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
    pub shutdown_grace_seconds: u64,
    pub client_ip_header: Option<String>,
    /// CIDR allowlist of trusted L4/L7 proxies. When non-empty, `CLIENT_IP_HEADER`
    /// is honored ONLY for connections whose direct peer IP falls in one of these
    /// CIDRs. When empty AND `client_ip_header` is set, the server emits a startup
    /// warning about spoofing risk (operator-trap mitigation).
    pub client_ip_header_trusted_cidrs: Vec<ipnet::IpNet>,
    pub proxy_protocol: ProxyProtocolMode,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
    pub tls_require_client_cert: bool,
    pub tls_client_ca_file: Option<PathBuf>,
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
            shutdown_grace_seconds: env_value_as_u64("SHUTDOWN_GRACE_SECONDS", 30),
            client_ip_header: env_opt("CLIENT_IP_HEADER"),
            client_ip_header_trusted_cidrs: parse_trusted_cidrs(
                env_opt("CLIENT_IP_HEADER_TRUSTED_CIDRS").as_deref(),
            ),
            proxy_protocol,
            tls_cert_file: env_opt("TLS_CERT_FILE").map(PathBuf::from),
            tls_key_file: env_opt("TLS_KEY_FILE").map(PathBuf::from),
            tls_require_client_cert: env_bool("TLS_REQUIRE_CLIENT_CERT", false),
            tls_client_ca_file: env_opt("TLS_CLIENT_CA_FILE").map(PathBuf::from),
        }
    }
}

/// Parse a comma-separated list of CIDR allowlist entries from `CLIENT_IP_HEADER_TRUSTED_CIDRS`.
/// Invalid entries are logged and skipped. An empty input yields an empty Vec.
fn parse_trusted_cidrs(s: Option<&str>) -> Vec<ipnet::IpNet> {
    let Some(s) = s else { return Vec::new() };
    let mut out = Vec::new();
    for raw in s.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        match raw.parse::<ipnet::IpNet>() {
            Ok(net) => out.push(net),
            Err(e) => warn!("ignoring invalid CIDR `{raw}` in CLIENT_IP_HEADER_TRUSTED_CIDRS: {e}"),
        }
    }
    out
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
    pub tls: Option<tls::TlsAcceptor>,
    pub active_count: Arc<std::sync::atomic::AtomicU64>,
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

    // Operator-trap mitigation: warn loudly if CLIENT_IP_HEADER is set without
    // a trusted-proxy CIDR allowlist. Direct connections to the server can spoof
    // the header otherwise.
    if cfg.client_ip_header.is_some() && cfg.client_ip_header_trusted_cidrs.is_empty() {
        warn!(
            header = ?cfg.client_ip_header,
            "CLIENT_IP_HEADER is set without CLIENT_IP_HEADER_TRUSTED_CIDRS — direct \
             connections can spoof the IP. Set CLIENT_IP_HEADER_TRUSTED_CIDRS to a \
             comma-separated list of LB CIDRs to gate header trust."
        );
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

    let tls = match (cfg.tls_cert_file.as_ref(), cfg.tls_key_file.as_ref()) {
        (Some(cert), Some(key)) => Some(tls::load_tls(
            cert,
            key,
            cfg.tls_require_client_cert,
            cfg.tls_client_ca_file.as_deref(),
        )?),
        (None, None) => None,
        _ => anyhow::bail!("TLS_CERT_FILE and TLS_KEY_FILE must be set together"),
    };

    Ok(Arc::new(Server {
        cfg,
        auth,
        metrics,
        health,
        shutdown,
        force_close,
        tls,
        active_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    }))
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
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking on pre-bound tunnel listener");
    let listener = TcpListener::from_std(listener).expect("convert std tunnel listener to tokio");

    if worker_idx == 0 {
        spawn_signal_handler(
            server.shutdown.clone(),
            server.force_close.clone(),
            server.health.clone(),
        );

        if server.cfg.reload_interval_seconds > 0 {
            server
                .auth
                .spawn_reload_watcher(Duration::from_secs(server.cfg.reload_interval_seconds));
        }

        if let Some(ml) = metrics_listener {
            ml.set_nonblocking(true)
                .expect("set_nonblocking on metrics listener");
            let listener =
                TcpListener::from_std(ml).expect("convert std metrics listener to tokio");
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
pub fn build_tunnel_listener_std(bind: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
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
        let _ = sock.set_reuse_port(true);
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
    sock.listen(1024)?;
    Ok(sock.into())
}

/// Build a TCP listener for the metrics service with SO_REUSEPORT set so the
/// pre-bind ordering rule (all binds succeed before any accept) holds.
pub fn build_metrics_listener_std(bind: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
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
        let _ = sock.set_reuse_port(true);
    }
    sock.bind(&bind.into())?;
    sock.listen(1024)?;
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
                        warn!("accept error: {e}");
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
    tokio::select! {
        _ = tokio::time::sleep(grace + Duration::from_secs(1)) => {
            info!("grace period elapsed; exiting");
        }
        _ = force_close.cancelled() => {
            warn!("second signal received; force-closing all tunnels with 1012");
            // Tunnel tasks observe `force_close` directly and will send 1012 immediately.
            // Give them a tight bound (500ms) to flush before we return and let the
            // runtime drop everything.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

fn spawn_signal_handler(
    shutdown: CancellationToken,
    force_close: CancellationToken,
    health: Arc<HealthState>,
) {
    tokio::spawn(async move {
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut intr = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut signals = 0u32;
        loop {
            tokio::select! {
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
}
