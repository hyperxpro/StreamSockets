//! HTTP/1.1 upgrade handshake: header validation, token auth, IP/CIDR check, lease.
//!
//! Mirrors `server/AuthenticationHandler.java` and `WebSocketServerInitializer.java`.
//! v2 protocol per MIGRATION.md §5.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use fastwebsockets::upgrade;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::proxy_protocol::{self, ProxyOutcome};
use crate::tunnel;
use crate::Server;

const HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;

/// Top-level entry: accept a TCP, optional PROXY-proto strip, optional TLS, hyper HTTP/1 upgrade.
pub async fn serve_connection(server: Arc<Server>, mut stream: TcpStream, peer: SocketAddr) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("set_nodelay failed: {e}");
    }

    // Capacity guard.
    if server.cfg.max_concurrent_connections > 0 {
        let cur = server.active_count.load(Ordering::SeqCst);
        if cur >= server.cfg.max_concurrent_connections {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["capacity"])
                .inc();
            warn!(peer = %peer, "rejecting at capacity ({})", cur);
            let _ = write_503(stream).await;
            return;
        }
    }
    server.active_count.fetch_add(1, Ordering::SeqCst);
    let active_guard = ActiveGuard {
        counter: server.active_count.clone(),
    };

    // PROXY-protocol parsing (optional). Replaces `peer` with the real client.
    let effective_peer =
        match proxy_protocol::process(&mut stream, server.cfg.proxy_protocol, peer).await {
            Ok(ProxyOutcome::Replaced(addr)) => addr,
            Ok(ProxyOutcome::Untouched) => peer,
            Ok(ProxyOutcome::Reject(reason)) => {
                server
                    .metrics
                    .handshake_failures
                    .with_label_values(&["bad_request"])
                    .inc();
                warn!(peer = %peer, "PROXY-protocol reject: {reason}");
                drop(active_guard);
                return;
            }
            Err(e) => {
                warn!(peer = %peer, "PROXY-protocol IO error: {e}");
                drop(active_guard);
                return;
            }
        };

    // TLS accept itself gets a hard deadline; subsequent HTTP read uses
    // hyper's builder-level header_read_timeout.
    let handshake_deadline = std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS);

    let result = if let Some(acceptor) = &server.tls {
        match tokio::time::timeout(handshake_deadline, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => serve_http(server.clone(), tls_stream, effective_peer).await,
            Ok(Err(e)) => {
                server
                    .metrics
                    .tls_handshake_failures
                    .with_label_values(&["accept_error"])
                    .inc();
                warn!(peer = %effective_peer, "TLS accept failed: {e}");
                Ok(())
            }
            Err(_) => {
                server.metrics.handshake_timeouts.inc();
                server
                    .metrics
                    .tls_handshake_failures
                    .with_label_values(&["timeout"])
                    .inc();
                warn!(peer = %effective_peer, "TLS handshake timed out");
                Ok(())
            }
        }
    } else {
        serve_http(server.clone(), stream, effective_peer).await
    };

    if let Err(e) = result {
        debug!("connection finished with error: {e}");
    }
    drop(active_guard);
}

struct ActiveGuard {
    counter: Arc<std::sync::atomic::AtomicU64>,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn write_503(mut stream: TcpStream) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let body = b"capacity\n";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nRetry-After: 5\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_http<S>(server: Arc<Server>, stream: S, peer: SocketAddr) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let io = TokioIo::new(stream);
    let server_for_svc = server.clone();
    let metrics = server.metrics.clone();
    let svc = service_fn(move |req| {
        let server = server_for_svc.clone();
        Box::pin(async move { handle_request(server, peer, req).await })
            as Pin<Box<dyn Future<Output = _> + Send>>
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS));

    match builder.serve_connection(io, svc).with_upgrades().await {
        Ok(()) => {}
        Err(e) => {
            // Header-read timeout shows up here; bump metric.
            let s = e.to_string();
            if s.contains("header") && s.contains("timeout") {
                metrics.handshake_timeouts.inc();
            }
            debug!("http1 conn error: {e}");
        }
    }
    Ok(())
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

async fn handle_request(
    server: Arc<Server>,
    peer: SocketAddr,
    mut req: Request<Incoming>,
) -> Result<Response<BoxBody>, std::io::Error> {
    let path = req.uri().path().to_string();
    if path != server.cfg.ws_path {
        return Ok(text_resp(StatusCode::NOT_FOUND, "not found"));
    }

    if !upgrade::is_upgrade_request(&req) {
        // RFC 6455 §4.4: 426 Upgrade Required.
        let mut resp = text_resp(StatusCode::UPGRADE_REQUIRED, "upgrade required");
        resp.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("websocket"));
        resp.headers_mut()
            .insert("Sec-WebSocket-Version", HeaderValue::from_static("13"));
        return Ok(resp);
    }

    // ── Validate v2 headers ───────────────────────────────────────────────
    let headers = req.headers().clone();

    let auth_type = headers.get("X-Auth-Type").and_then(|v| v.to_str().ok());
    if !matches!(auth_type, Some(t) if t.eq_ignore_ascii_case("Token")) {
        server
            .metrics
            .handshake_failures
            .with_label_values(&["bad_request"])
            .inc();
        return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
    }

    let token = match headers.get("X-Auth-Token").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
        }
    };

    let route_address = headers.get("X-Route-Address").and_then(|v| v.to_str().ok());
    let route_port = headers.get("X-Route-Port").and_then(|v| v.to_str().ok());
    let (route_address, route_port) = match (route_address, route_port) {
        (Some(a), Some(p)) => {
            // Strip IPv6 brackets — `[::1]` is URL host syntax, not address syntax.
            // `IpAddr::parse` rejects bracketed forms, so keeping them would route
            // any IPv6 literal through DNS as a hostname → 1011.
            let stripped = a
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .unwrap_or(a);
            (stripped.to_string(), p.to_string())
        }
        _ => {
            // v1-style legacy-route request without v2 X-Route-* headers — reject as
            // bad_request (per docs/v2.md §1.1, v1 wire protocol is removed).
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
        }
    };

    // X-StreamSockets-Version: optional, but if present and != "2", reject.
    if let Some(v) = headers
        .get("X-StreamSockets-Version")
        .and_then(|v| v.to_str().ok())
    {
        if v != "2" {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            let mut resp = text_resp(StatusCode::BAD_REQUEST, "version mismatch");
            resp.headers_mut()
                .insert("X-StreamSockets-Version", HeaderValue::from_static("2"));
            return Ok(resp);
        }
    }

    let port_num: u16 = match route_port.parse() {
        Ok(p) => p,
        Err(_) => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
        }
    };

    let route_string = format!("{route_address}:{port_num}");

    // CLIENT_IP_HEADER is honored only when the direct peer is in an explicitly
    // trusted CIDR (`CLIENT_IP_HEADER_TRUSTED_CIDRS`). Otherwise we fall back to
    // the direct peer IP. This closes the spoofing trap (Pass 5 SHIP-BLOCKER #21):
    // an attacker reaching the server directly cannot inject `X-Forwarded-For:
    // <whitelisted-ip>` to bypass `allowedIps`.
    let header_trusted = !server.cfg.client_ip_header_trusted_cidrs.is_empty()
        && server
            .cfg
            .client_ip_header_trusted_cidrs
            .iter()
            .any(|net| net.contains(&peer.ip()));
    let client_ip = if let Some(h) = &server.cfg.client_ip_header {
        if header_trusted {
            headers
                .get(h.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        } else if server.cfg.client_ip_header_trusted_cidrs.is_empty() {
            // Allowlist not configured — preserve legacy behavior (trust header)
            // but the startup log warned the operator about spoofing risk.
            headers
                .get(h.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        } else {
            // Allowlist configured but direct peer not in it — ignore header and
            // use direct peer IP. Bump a metric so operators can spot misconfig.
            server
                .metrics
                .protocol_violations
                .with_label_values(&["client_ip_header_untrusted"])
                .inc();
            peer.ip().to_string()
        }
    } else {
        peer.ip().to_string()
    };
    if client_ip.is_empty() {
        server
            .metrics
            .handshake_failures
            .with_label_values(&["bad_request"])
            .inc();
        return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
    }

    // ── Auth ──────────────────────────────────────────────────────────────
    // Defense-in-depth timing safety: HashMap lookup followed by constant-time
    // re-verify of the token bytes. See streamsockets-auth::AccountsSnapshot::authenticate.
    use subtle::ConstantTimeEq;
    let snap = server.auth.snapshot_arc();
    let cache_opt = snap.by_token.get(&token).cloned();
    let cache = match cache_opt {
        Some(c)
            if c.account.token.len() == token.len()
                && bool::from(c.account.token.as_bytes().ct_eq(token.as_bytes())) =>
        {
            c
        }
        _ => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["auth"])
                .inc();
            warn!(client_ip = %client_ip, "auth fail (token unknown)");
            let mut resp = text_resp(StatusCode::UNAUTHORIZED, "unauthorized");
            resp.headers_mut()
                .insert("WWW-Authenticate", HeaderValue::from_static("Token"));
            return Ok(resp);
        }
    };

    // Route check
    if !cache.route_set.contains(&route_string) {
        server
            .metrics
            .handshake_failures
            .with_label_values(&["route_denied"])
            .inc();
        warn!(account = %cache.account.name, client_ip = %client_ip, route = %route_string, "route denied");
        return Ok(text_resp(StatusCode::FORBIDDEN, "Route not allowed"));
    }

    // IP check
    let ip_parsed: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
        }
    };
    let allowed = cache.allowed_cidrs.iter().any(|n| n.contains(&ip_parsed));
    if !allowed {
        server
            .metrics
            .handshake_failures
            .with_label_values(&["ip_denied"])
            .inc();
        warn!(account = %cache.account.name, client_ip = %client_ip, "IP denied");
        return Ok(text_resp(StatusCode::FORBIDDEN, "IP not allowed"));
    }

    // Lease
    let lease = match server.auth.leases().try_lease_arc(&cache.account) {
        Ok(g) => g,
        Err(_) => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["reuse_conflict"])
                .inc();
            warn!(account = %cache.account.name, "reuse conflict");
            return Ok(text_resp(StatusCode::CONFLICT, "Account already in use"));
        }
    };

    // Echo Sec-WebSocket-Protocol if client sent v2 marker.
    let echo_subprotocol = headers
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| s.split(',').any(|p| p.trim() == "streamsockets.v2"));

    server
        .metrics
        .handshake_version
        .with_label_values(&["v2"])
        .set(1.0);

    // Begin upgrade.
    let (mut response, fut) = match upgrade::upgrade(&mut req) {
        Ok(p) => p,
        Err(e) => {
            warn!("websocket upgrade preparation failed: {e}");
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad upgrade"));
        }
    };

    if let Some(proto) = echo_subprotocol {
        if let Ok(v) = HeaderValue::from_str(&proto) {
            response.headers_mut().insert("Sec-WebSocket-Protocol", v);
        }
    }
    response
        .headers_mut()
        .insert("X-StreamSockets-Version", HeaderValue::from_static("2"));

    let account_name = cache.account.name.clone();
    let server_for_tunnel = server.clone();
    let max_frame = server.cfg.max_frame_size;
    let tunnel_id = uuid::Uuid::new_v4();
    info!(
        account = %account_name,
        client_ip = %client_ip,
        route = %route_string,
        tunnel_id = %tunnel_id,
        "handshake ok"
    );

    tokio::spawn(async move {
        match fut.await {
            Ok(ws) => {
                // Record connection start only when the upgrade actually succeeded.
                // This keeps `streamsockets_active_connections` consistent — we
                // increment and decrement under the same condition.
                server_for_tunnel
                    .metrics
                    .record_connection_start(&account_name);
                let started = std::time::Instant::now();
                let res = tunnel::run_tunnel(
                    server_for_tunnel.clone(),
                    ws,
                    route_address,
                    port_num,
                    max_frame,
                    account_name.clone(),
                    client_ip,
                    tunnel_id,
                )
                .await;
                let dur = started.elapsed().as_secs_f64();
                server_for_tunnel
                    .metrics
                    .record_connection_end(&account_name, dur);
                if let Err(e) = res {
                    debug!(account = %account_name, "tunnel ended: {e}");
                }
                drop(lease);
            }
            Err(e) => {
                warn!(account = %account_name, "ws upgrade future failed: {e}");
                server_for_tunnel
                    .metrics
                    .handshake_failures
                    .with_label_values(&["upgrade_failed"])
                    .inc();
                drop(lease);
            }
        }
    });

    let (parts, _) = response.into_parts();
    Ok(Response::from_parts(parts, empty_body()))
}

fn text_resp(status: StatusCode, body: &'static str) -> Response<BoxBody> {
    use http_body_util::BodyExt;
    let body = http_body_util::Full::new(Bytes::from_static(body.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    // Static body + valid status: builder cannot fail. `expect` documents the
    // invariant for future maintainers (replaces a bare `.unwrap()`).
    Response::builder()
        .status(status)
        .body(body)
        .expect("text_resp inputs are static and always valid")
}

fn empty_body() -> BoxBody {
    use http_body_util::BodyExt;
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
