//! Shared helpers for integration tests.
//!
//! Counter isolation strategy: tests that assert on Prometheus counters
//! (e.g. `streamsockets_handshake_failures_total{reason="bad_request"}`)
//! use a snapshot-then-delta pattern rather than absolute values. The
//! `Metrics::global()` registry is process-global; binaries that exercise
//! multiple counter-asserting tests will see counter bleed across tests.
//! Use [`scrape_metrics`] + [`parse_counter_sample`] so each test reads a
//! baseline before its action and asserts a delta ≥ N.
//!
//! Server lifecycle: [`spawn_server`] returns a [`ServerGuard`] holding a
//! `CancellationToken`. Tests that re-bind the same TCP port MUST call
//! `guard.stop().await` first — `JoinHandle::abort()` does NOT release the
//! listening socket synchronously.
#![allow(dead_code)] // each test binary uses a different subset.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use streamsockets_auth::TokenAuthentication;
use tempfile::NamedTempFile;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Write a minimal accounts.yaml and return its path.
pub fn write_accounts(yaml: &str) -> NamedTempFile {
    use std::io::Write;
    let mut tf = NamedTempFile::new().unwrap();
    tf.write_all(yaml.as_bytes()).unwrap();
    tf.flush().unwrap();
    tf
}

pub fn default_accounts_yaml(udp_port: u16) -> String {
    format!(
        r#"
accounts:
  - name: alice
    token: 'secret-token'
    reuse: false
    routes:
      - '127.0.0.1:{}'
    allowedIps:
      - '127.0.0.1'
      - '::1'
"#,
        udp_port
    )
}

/// Spawn a tokio task running an echo UDP server on `127.0.0.1:0`. Returns the bound port.
pub async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (port, handle)
}

/// Default test server config. `metrics_enabled: true` so tests can assert on
/// counters (e.g. `streamsockets_handshake_failures_total{reason="bad_request"}`).
pub fn default_server_cfg(
    bind_port: u16,
    accounts_path: std::path::PathBuf,
    metrics_port: u16,
) -> streamsockets_server::ServerConfig {
    streamsockets_server::ServerConfig {
        bind_address: "127.0.0.1".into(),
        bind_port,
        ws_path: "/tunnel".into(),
        max_frame_size: 65536,
        http_max_content_length: 65536,
        accounts_file: accounts_path,
        reload_interval_seconds: 0,
        // metrics_enabled: keep ON so v1-rejection (etc.) tests can scrape counters.
        // Random metrics_port is supplied by callers so concurrent test bins don't collide.
        metrics_enabled: true,
        metrics_bind_address: "127.0.0.1".into(),
        metrics_port,
        metrics_path: "/metrics".into(),
        max_concurrent_connections: 0,
        per_ip_max_concurrent: 0,
        shutdown_grace_seconds: 1,
        client_ip_header: None,
        client_ip_header_trusted_cidrs: Vec::new(),
        proxy_protocol: streamsockets_server::ProxyProtocolMode::Disabled,
        proxy_protocol_trusted_cidrs: Vec::new(),
        tls_cert_file: None,
        tls_key_file: None,
        tls_require_client_cert: false,
        tls_client_ca_file: None,
        // Tests bind metrics on 127.0.0.1 explicitly above; opt in to allow it
        // for completeness so a future test that sets a wildcard doesn't trip
        // the production guard.
        metrics_bind_all: true,
        listen_backlog: 1024,
    }
}

/// RAII handle returned by [`spawn_server`]. Drop calls `cancel()` so a
/// test that early-returns doesn't leave the listener bound on the port.
/// Tests that need the same port for a restart must call `stop().await`
/// (which awaits drain + listener-close) before re-binding.
///
/// `handle` is `Option<JoinHandle>` so `stop()` can take ownership of the
/// JoinHandle while `Drop` is still implemented — moving fields out of a
/// `Drop` type otherwise requires `ManuallyDrop`, which is heavier.
pub struct ServerGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
    pub shutdown: CancellationToken,
    pub bind_port: u16,
    pub metrics_port: u16,
}

impl ServerGuard {
    /// Cancel and await graceful shutdown. After this returns, the
    /// kernel has released the TCP listener and the same port is rebindable.
    pub async fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(h) = self.handle.take() {
            // The accept loop drops its `TcpListener` when `shutdown` fires;
            // the `JoinHandle` future completes when the task returns. Bound
            // timeout so a wedged drain doesn't hang the test forever.
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        // Detach: signal cancel, leave the handle to be reaped by the runtime.
        // Tests that need port-reuse must call `stop().await` instead.
        self.shutdown.cancel();
    }
}

/// Build a `streamsockets-server` and run on the given port. The returned
/// guard owns a `CancellationToken` — drop it (or call `stop().await`) to tear
/// the server down. `JoinHandle::abort()` does NOT close the TCP listener
/// synchronously; tests that re-bind the same port MUST `stop().await`.
pub async fn spawn_server(
    bind_port: u16,
    accounts_path: std::path::PathBuf,
    metrics_port: u16,
) -> ServerGuard {
    let cfg = default_server_cfg(bind_port, accounts_path, metrics_port);
    let shutdown = CancellationToken::new();
    let s = shutdown.clone();
    let handle = tokio::spawn(async move {
        let _ = run_server_with_cfg(cfg, s).await;
    });
    let guard = ServerGuard {
        handle: Some(handle),
        shutdown,
        bind_port,
        metrics_port,
    };
    // Block on a TCP readiness probe so callers don't need their own
    // `settle()` after spawn. Bounded — if the bind fails the test will
    // surface it via the next operation.
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let _ = wait_for_server_ready(addr, Duration::from_secs(5)).await;
    guard
}

/// Re-implementation of `run()` that accepts a programmatic `ServerConfig` (for tests).
/// Spawns a metrics HTTP listener if `cfg.metrics_enabled` is true. Honors the
/// passed-in `shutdown` token so the test harness can drive graceful drain.
pub async fn run_server_with_cfg(
    cfg: streamsockets_server::ServerConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    use std::sync::atomic::AtomicU64;
    use streamsockets_metrics::{HealthState, Metrics};
    use tokio::net::TcpListener;

    let cfg = Arc::new(cfg);
    let auth = Arc::new(TokenAuthentication::from_file(&cfg.accounts_file)?);
    let metrics = Metrics::global();
    let health = Arc::new(HealthState::new());
    let force_close = CancellationToken::new();
    let reload = Arc::new(Notify::new());

    if cfg.metrics_enabled {
        let metrics_addr: SocketAddr =
            format!("{}:{}", cfg.metrics_bind_address, cfg.metrics_port).parse()?;
        let m = metrics.clone();
        let h = health.clone();
        let p = cfg.metrics_path.clone();
        let cancel = shutdown.clone();
        tokio::spawn(async move {
            let _ = streamsockets_metrics::serve_metrics_with_cancel(
                metrics_addr,
                m,
                h,
                p,
                false,
                Some(cancel),
            )
            .await;
        });
    } else {
        health.mark_ready();
    }

    let server = Arc::new(streamsockets_server::Server {
        cfg: cfg.clone(),
        auth,
        metrics,
        health,
        shutdown: shutdown.clone(),
        force_close: force_close.clone(),
        reload,
        tls: None,
        tls_resolver: None,
        active_count: Arc::new(AtomicU64::new(0)),
        per_ip: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
    });

    let bind: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.bind_port).parse()?;
    let listener = TcpListener::bind(bind).await?;
    let s = server.clone();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    let s = s.clone();
                    tokio::spawn(async move {
                        streamsockets_server::handshake::serve_connection(s, stream, peer).await;
                    });
                }
                Err(_) => break,
            }
        }
    }
    // Drop `listener` so the kernel releases the FD before this future
    // returns — the test harness rebinds the same port immediately after.
    drop(listener);
    Ok(())
}

/// Pick a free TCP port + free UDP port near each other.
pub async fn free_tcp_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
pub async fn free_udp_port() -> u16 {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

/// Block until `addr` accepts a TCP connection or `timeout` elapses. Returns
/// `Ok(())` on first successful connect. The probe socket is dropped
/// immediately — it does NOT consume the server's connection budget.
pub async fn wait_for_server_ready(addr: SocketAddr, timeout: Duration) -> Result<(), io::Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match TcpStream::connect(addr).await {
            Ok(s) => {
                drop(s);
                return Ok(());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "server not ready"))
}

/// Block until `http://127.0.0.1:{port}/metrics` returns 200 with a body, or
/// `timeout` elapses. Used to gate tests on the metrics endpoint being live.
pub async fn wait_for_metrics_ready(port: u16, timeout: Duration) -> Result<(), io::Error> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_util::rt::TokioIo;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)).await {
            let io = TokioIo::new(tcp);
            if let Ok((mut sender, conn)) =
                hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io).await
            {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = Request::builder()
                    .uri("/metrics")
                    .header("Host", format!("127.0.0.1:{port}"))
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                if let Ok(resp) = sender.send_request(req).await {
                    if resp.status().as_u16() == 200 {
                        let _ = resp.into_body().collect().await;
                        return Ok(());
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "metrics not ready"))
}

/// Spawn a `streamsockets-client` configured against the test server. Returns
/// the (handle, shutdown_token) so the test can request graceful exit.
pub async fn spawn_client(
    cfg: streamsockets_client::ClientConfig,
) -> (tokio::task::JoinHandle<()>, CancellationToken) {
    let shutdown = CancellationToken::new();
    let s = shutdown.clone();
    let h = tokio::spawn(async move {
        let cfg = Arc::new(cfg);
        let _ = streamsockets_client::fsm::run_fsm(cfg, s).await;
    });
    (h, shutdown)
}

pub fn default_client_cfg(
    server_port: u16,
    udp_port: u16,
    upstream_port: u16,
) -> streamsockets_client::ClientConfig {
    streamsockets_client::ClientConfig {
        bind_address: "127.0.0.1".into(),
        bind_port: udp_port,
        websocket_uri: format!("ws://127.0.0.1:{server_port}/tunnel"),
        auth_token: streamsockets_client::RedactedString::new("secret-token".into()),
        route: format!("127.0.0.1:{upstream_port}"),
        ping_interval_ms: 1000,
        ping_timeout_ms: 5000,
        ping_permitted_misses: 1,
        retry_initial_delay_ms: 100,
        retry_max_delay_ms: 1000,
        retry_budget: 5,
        udp_timeout_secs: 60,
        exit_on_failure: false,
        queue_max_bytes: 1024 * 1024,
        queue_drain_timeout_ms: 5000,
        threads: 1,
        max_frame_size: 65536,
        udp_channel_capacity: 1024,
        // Tests use ws:// (no TLS) but pass a non-empty token; default-deny
        // would reject these handshakes — explicitly allow.
        allow_insecure_auth: true,
        // We always supply a token in test configs; default-deny is fine.
        allow_no_auth: false,
        tls_ca_file: None,
    }
}

pub fn init_tracing_for_tests() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// Best-effort delay used in places where there is no readiness signal to
/// probe (e.g., waiting for an in-flight UDP packet to be flushed). Prefer
/// [`wait_for_server_ready`] / [`wait_for_metrics_ready`] for server bring-up.
pub async fn settle(d: Duration) {
    tokio::time::sleep(d).await;
}

/// Scrape `/metrics` once and return the body. Hand-rolled HTTP/1.1 GET so
/// the test crate doesn't pull in `reqwest`.
pub async fn scrape_metrics(port: u16) -> String {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_util::rt::TokioIo;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/metrics")
        .header("Host", format!("127.0.0.1:{port}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap_or_default()
}

/// Parse a single Prometheus counter/gauge sample. `metric_name` is the bare
/// metric (no `{labels}`); the line MUST contain every fragment in
/// `label_fragments` (e.g. `r#"reason="bad_request""#`). Returns 0.0 when no
/// matching line is found, so callers can do snapshot-then-delta arithmetic
/// without a special "first scrape" branch.
pub fn parse_counter_sample(body: &str, metric_name: &str, label_fragments: &[&str]) -> f64 {
    body.lines()
        .filter(|l| l.starts_with(metric_name))
        .filter(|l| label_fragments.iter().all(|f| l.contains(f)))
        .find_map(|l| {
            l.split_whitespace()
                .last()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

/// Poll `/metrics` until the gauge or counter `metric_name{labels...}` reaches
/// at least `threshold`, or `timeout` elapses. Returns the last observed value
/// on success; `Err(last_observed)` on timeout for diagnostics.
pub async fn wait_for_metric_at_least(
    port: u16,
    metric_name: &str,
    label_fragments: &[&str],
    threshold: f64,
    timeout: Duration,
) -> Result<f64, f64> {
    let deadline = Instant::now() + timeout;
    let mut last = 0.0;
    while Instant::now() < deadline {
        let body = scrape_metrics(port).await;
        last = parse_counter_sample(&body, metric_name, label_fragments);
        if last >= threshold {
            return Ok(last);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last)
}
