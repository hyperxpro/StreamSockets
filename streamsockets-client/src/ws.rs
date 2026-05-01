//! WS dial: TCP/TLS connect → HTTP/1.1 upgrade with v2 headers → fastwebsockets handle.

use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
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

pub enum DialError {
    Tcp(std::io::Error),
    Tls(std::io::Error),
    Http(hyper::Error),
    HandshakeStatus(http::StatusCode),
    BadUri(String),
    Other(String),
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
        }
    }
}

impl DialError {
    /// Should the FSM treat this as terminal (no retry)?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DialError::HandshakeStatus(s)
                if s.as_u16() == 401 || s.as_u16() == 403 || s.as_u16() == 409
        ) || matches!(self, DialError::BadUri(_))
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            DialError::HandshakeStatus(s) => Some(s.as_u16()),
            _ => None,
        }
    }
}

pub type WsHandle = fastwebsockets::WebSocket<TokioIo<hyper::upgrade::Upgraded>>;

/// Dial the v2 WebSocket. Returns the upgraded WebSocket on success.
///
/// Equivalent to `dial_with_progress(cfg, || {})` — kept for callers that don't
/// care about the Connecting → Authenticating transition boundary.
pub async fn dial(cfg: &ClientConfig) -> Result<WsHandle, DialError> {
    dial_with_progress(cfg, || {}).await
}

/// Dial the v2 WebSocket with an `on_authenticating` callback fired once the
/// transport (TCP, optionally TLS) is up and just before the HTTP/1.1 upgrade
/// is sent. Per MIGRATION.md §6.1 / §6 the FSM uses this hook to flip the
/// `client_state` metric from `connecting` to `authenticating` precisely when
/// "TCP up, waiting for 101" first holds.
///
/// The callback runs synchronously and must not block; in practice the FSM
/// passes a closure that mutates a local `State` and updates a Prometheus
/// gauge.
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
    let host = url
        .host_str()
        .ok_or_else(|| DialError::BadUri("missing host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DialError::BadUri("missing port".into()))?;
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(DialError::Tcp)?;
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
        let connector = build_tls_connector().map_err(DialError::Tls)?;
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| {
                DialError::Tls(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
            })?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(DialError::Tls)?;
        // Transport (TCP+TLS) is up — the FSM should now reflect Authenticating.
        on_authenticating();
        do_handshake(tls, req).await
    } else {
        // Plain TCP: transport up is the TCP connect; flip Authenticating now.
        on_authenticating();
        do_handshake(tcp, req).await
    }
}

async fn do_handshake<S>(stream: S, req: Request<Empty<Bytes>>) -> Result<WsHandle, DialError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (ws, response) = handshake::client(&TokioExec, req, stream)
        .await
        .map_err(|e| DialError::Other(e.to_string()))?;
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(DialError::HandshakeStatus(response.status()));
    }
    Ok(ws)
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

    // RFC 9110: omit the port from Host when it matches the default for the scheme.
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

fn build_tls_connector() -> std::io::Result<TlsConnector> {
    // Use platform verifier (OS root store) — matches Java's relying on JDK trust.
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    let verifier = rustls_platform_verifier::Verifier::new();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    // ALPN: announce http/1.1 explicitly so servers that gate WS upgrade on it
    // (e.g. some k8s ingresses) don't reject the handshake.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}
