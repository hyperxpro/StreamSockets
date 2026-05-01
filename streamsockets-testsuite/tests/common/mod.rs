//! Shared helpers for integration tests.
#![allow(dead_code)] // each test binary uses a different subset.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use streamsockets_auth::TokenAuthentication;
use tempfile::NamedTempFile;
use tokio::net::UdpSocket;
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
        shutdown_grace_seconds: 1,
        client_ip_header: None,
        client_ip_header_trusted_cidrs: Vec::new(),
        proxy_protocol: streamsockets_server::ProxyProtocolMode::Disabled,
        tls_cert_file: None,
        tls_key_file: None,
        tls_require_client_cert: false,
        tls_client_ca_file: None,
    }
}

/// Build a `streamsockets-server` and run on the given port.
pub async fn spawn_server(
    bind_port: u16,
    accounts_path: std::path::PathBuf,
    metrics_port: u16,
) -> tokio::task::JoinHandle<()> {
    let cfg = default_server_cfg(bind_port, accounts_path, metrics_port);
    tokio::spawn(async move {
        let _ = run_server_with_cfg(cfg).await;
    })
}

/// Re-implementation of `run()` that accepts a programmatic `ServerConfig` (for tests).
/// Spawns a metrics HTTP listener if `cfg.metrics_enabled` is true.
pub async fn run_server_with_cfg(cfg: streamsockets_server::ServerConfig) -> anyhow::Result<()> {
    use std::sync::atomic::AtomicU64;
    use streamsockets_metrics::{HealthState, Metrics};
    use tokio::net::TcpListener;

    let cfg = Arc::new(cfg);
    let auth = Arc::new(TokenAuthentication::from_file(&cfg.accounts_file)?);
    let metrics = Metrics::global();
    let health = Arc::new(HealthState::new());
    let shutdown = CancellationToken::new();
    let force_close = CancellationToken::new();

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
        tls: None,
        active_count: Arc::new(AtomicU64::new(0)),
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

pub async fn settle(d: Duration) {
    tokio::time::sleep(d).await;
}
