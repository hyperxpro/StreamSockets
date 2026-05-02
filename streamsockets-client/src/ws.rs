//! WS dial: TCP/TLS connect → HTTP/1.1 upgrade with v2 headers → fastwebsockets handle.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use dashmap::DashMap;
use fastwebsockets::handshake;
use http::Request;
use http_body_util::Empty;
use hyper::rt::Executor;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::ClientConfig;

/// Hard cap on each TCP connect attempt. Without this a black-holed SYN waits
/// the kernel's ~75 s timeout while the FSM's retry budget never decrements.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// RFC 8305 head-start for v4 when v6 is in flight.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
/// DNS cache TTL. Reconnect storms otherwise saturate the blocking pool with
/// repeated `getaddrinfo`. (#12)
const DNS_CACHE_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Default)]
pub struct TokioExec;
impl<F> Executor<F> for TokioExec
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

#[derive(Debug)]
pub enum DialError {
    Tcp(std::io::Error),
    Tls(std::io::Error),
    Http(hyper::Error),
    HandshakeStatus(http::StatusCode),
    BadUri(String),
    Other(String),
    /// Refused at dial time (#1): ws:// + AUTH_TOKEN would put the token on the wire.
    InsecureScheme,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Tcp(e) => write!(f, "tcp: {e}"),
            DialError::Tls(e) => write!(f, "tls: {e}"),
            DialError::Http(e) => write!(f, "http: {e}"),
            DialError::HandshakeStatus(s) => write!(f, "handshake status: {s}"),
            DialError::BadUri(s) => write!(f, "bad uri: {s}"),
            DialError::Other(s) => write!(f, "other: {s}"),
            DialError::InsecureScheme => write!(
                f,
                "refusing to send AUTH_TOKEN over ws://; use wss:// or set ALLOW_INSECURE_AUTH=true"
            ),
        }
    }
}

impl DialError {
    /// Should the FSM treat this as terminal (no retry)?
    ///
    /// The terminal HTTP-status set is exactly `401`, `403`, `409`. Every
    /// other status code is treated as transient and retried (subject to
    /// `RETRY_BUDGET`).
    pub fn is_terminal(&self) -> bool {
        if let DialError::HandshakeStatus(s) = self {
            return matches!(s.as_u16(), 401 | 403 | 409);
        }
        matches!(self, DialError::BadUri(_) | DialError::InsecureScheme)
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            DialError::HandshakeStatus(s) => Some(s.as_u16()),
            _ => None,
        }
    }
}

pub type WsHandle = fastwebsockets::WebSocket<TokioIo<hyper::upgrade::Upgraded>>;

pub async fn dial(cfg: &ClientConfig) -> Result<WsHandle, DialError> {
    dial_with_progress(cfg, || {}).await
}

pub async fn dial_with_progress<F>(
    cfg: &ClientConfig,
    on_authenticating: F,
) -> Result<WsHandle, DialError>
where
    F: FnOnce(),
{
    let url = Url::parse(&cfg.websocket_uri).map_err(|e| DialError::BadUri(e.to_string()))?;
    let scheme = url.scheme();
    let use_tls = match scheme {
        "ws" => false,
        "wss" => true,
        other => return Err(DialError::BadUri(format!("unsupported scheme: {other}"))),
    };
    // (#1) Defense-in-depth: refuse plaintext-token transmission even if
    // config validation was bypassed (e.g. tests building ClientConfig literally).
    if !use_tls && !cfg.auth_token_str().is_empty() && !cfg.allow_insecure_auth {
        return Err(DialError::InsecureScheme);
    }
    let host = url
        .host_str()
        .ok_or_else(|| DialError::BadUri("missing host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DialError::BadUri("missing port".into()))?;
    if port == 0 {
        return Err(DialError::BadUri("port 0 is invalid".into()));
    }
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    // (#13) Real happy-eyeballs with cached DNS.
    let tcp = match happy_eyeballs_connect(host, port).await {
        Ok(s) => s,
        Err(e) => {
            dns_cache().remove(host);
            return Err(DialError::Tcp(e));
        }
    };
    let _ = tcp.set_nodelay(true);

    let (route_address, route_port) = crate::parse_route(&cfg.route)
        .ok_or_else(|| DialError::BadUri(format!("invalid ROUTE: {}", cfg.route)))?;

    let req = build_upgrade_request(
        host,
        port,
        use_tls,
        path,
        cfg.auth_token_str(),
        route_address,
        route_port,
    )
    .map_err(|e| DialError::Other(e.to_string()))?;

    if use_tls {
        // (#11) Cached connector — the platform verifier is expensive to build.
        let connector = tls_connector().clone();
        // (#14) Detect IP literal explicitly.
        let server_name = server_name_for(host).map_err(|e| {
            DialError::Tls(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(DialError::Tls)?;
        on_authenticating();
        do_handshake(tls, req).await
    } else {
        on_authenticating();
        do_handshake(tcp, req).await
    }
}

async fn do_handshake<S>(stream: S, req: Request<Empty<Bytes>>) -> Result<WsHandle, DialError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (ws, response) = match handshake::client(&TokioExec, req, stream).await {
        Ok(v) => v,
        // fastwebsockets reports a non-101 server response as
        // `WebSocketError::InvalidStatusCode(u16)`. Surface it as a typed
        // `HandshakeStatus` so `is_terminal()` can fire (e.g. 401 → terminal).
        Err(fastwebsockets::WebSocketError::InvalidStatusCode(code)) => {
            let status =
                http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
            return Err(DialError::HandshakeStatus(status));
        }
        Err(e) => return Err(DialError::Other(e.to_string())),
    };
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(DialError::HandshakeStatus(response.status()));
    }
    Ok(ws)
}

fn server_name_for(host: &str) -> Result<rustls::pki_types::ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid SNI host {host:?}: {e}"))
}

/// Bound on the in-process DNS cache. A pathological deployment that rotates
/// hostnames (e.g. probing CDNs) would otherwise grow this DashMap unbounded.
/// 256 entries is comfortably above any realistic per-process distinct-host
/// count for a tunnel client, and well under any memory concern.
const DNS_CACHE_MAX_ENTRIES: usize = 256;

fn dns_cache() -> &'static DashMap<String, (Vec<SocketAddr>, Instant)> {
    static CACHE: OnceLock<DashMap<String, (Vec<SocketAddr>, Instant)>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

async fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let cache = dns_cache();
    let now = Instant::now();
    if let Some(entry) = cache.get(host) {
        let (addrs, ts) = entry.value();
        if now.duration_since(*ts) < DNS_CACHE_TTL && !addrs.is_empty() {
            return Ok(addrs
                .iter()
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect());
        }
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if !resolved.is_empty() {
        // If the cache is at capacity, evict expired entries first; if still
        // over, evict the oldest. This is O(N) on insert but N is bounded by
        // DNS_CACHE_MAX_ENTRIES so the cost is trivial.
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.retain(|_, (_, ts)| now.duration_since(*ts) < DNS_CACHE_TTL);
            if cache.len() >= DNS_CACHE_MAX_ENTRIES {
                let oldest = cache
                    .iter()
                    .min_by_key(|kv| kv.value().1)
                    .map(|kv| kv.key().clone());
                if let Some(key) = oldest {
                    cache.remove(&key);
                }
            }
        }
        cache.insert(host.to_string(), (resolved.clone(), now));
    }
    Ok(resolved)
}

/// RFC 8305 happy-eyeballs connect with a hard timeout.
async fn happy_eyeballs_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addrs = resolve(host, port).await?;
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}"),
        ));
    }

    let v6: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv6()).collect();
    let v4: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();

    if v6.is_empty() {
        return connect_first(&v4, TCP_CONNECT_TIMEOUT).await;
    }
    if v4.is_empty() {
        return connect_first(&v6, TCP_CONNECT_TIMEOUT).await;
    }

    // (#13) v4 future is constructed once and pinned; v6 failure awaits this
    // exact future rather than re-firing a fresh connect.
    let v4_fut = async {
        tokio::time::sleep(HAPPY_EYEBALLS_DELAY).await;
        connect_first(&v4, TCP_CONNECT_TIMEOUT).await
    };
    tokio::pin!(v4_fut);
    let v6_fut = connect_first(&v6, TCP_CONNECT_TIMEOUT);
    tokio::pin!(v6_fut);
    tokio::select! {
        biased;
        r = &mut v6_fut => match r {
            Ok(s) => Ok(s),
            Err(_) => v4_fut.await,
        },
        r = &mut v4_fut => match r {
            Ok(s) => Ok(s),
            Err(_) => v6_fut.await,
        },
    }
}

async fn connect_first(addrs: &[SocketAddr], timeout: Duration) -> std::io::Result<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    for a in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(*a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("tcp connect to {a} timed out after {timeout:?}"),
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses")
    }))
}

fn build_upgrade_request(
    host: &str,
    port: u16,
    use_tls: bool,
    path: &str,
    token: &str,
    route_address: &str,
    route_port: u16,
) -> Result<Request<Empty<Bytes>>, http::Error> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);

    let host_hdr = match (use_tls, port) {
        (false, 80) | (true, 443) => host.to_string(),
        _ => format!("{host}:{port}"),
    };

    Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", host_hdr)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", key_b64)
        .header("Sec-WebSocket-Version", "13")
        .header("X-Auth-Type", "Token")
        .header("X-Auth-Token", token)
        .header("X-Route-Address", route_address)
        .header("X-Route-Port", route_port.to_string())
        .header("X-StreamSockets-Version", "2")
        .header("Sec-WebSocket-Protocol", "streamsockets.v2")
        .body(Empty::<Bytes>::new())
}

/// (#11) Cached `TlsConnector`. The platform verifier loads the OS root
/// store on construction; doing so per-dial during a reconnect storm
/// causes file-descriptor pressure on Linux and Keychain syscall pressure
/// on macOS. Build once per process.
fn tls_connector() -> &'static Arc<TlsConnector> {
    static CACHE: OnceLock<Arc<TlsConnector>> = OnceLock::new();
    CACHE.get_or_init(|| {
        install_default_provider_once();
        let verifier = rustls_platform_verifier::Verifier::new();
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(TlsConnector::from(Arc::new(config)))
    })
}

fn install_default_provider_once() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
