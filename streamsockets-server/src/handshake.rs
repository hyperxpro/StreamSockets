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
use crate::{try_acquire_per_ip, PerIpGuard, Server};

const HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
/// Timeout for the WS upgrade future after the response has been written. A
/// stalled client otherwise pins the upgrade task until TCP keepalive fires.
const UPGRADE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Top-level entry: accept a TCP, optional PROXY-proto strip, optional TLS, hyper HTTP/1 upgrade.
pub async fn serve_connection(server: Arc<Server>, mut stream: TcpStream, peer: SocketAddr) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("set_nodelay failed: {e}");
    }

    // Global capacity guard. Atomic `fetch_add`-then-revert avoids the TOCTOU
    // window where N concurrent accepts each see `cur < max` and admit `max+N-1`.
    // `Relaxed` is sufficient — the counter is a single-word fence-free gauge,
    // and the global cap is intentionally approximate (slop of one is fine).
    let admitted = if server.cfg.max_concurrent_connections > 0 {
        let cap = server.cfg.max_concurrent_connections;
        let prev = server.active_count.fetch_add(1, Ordering::Relaxed);
        if prev >= cap {
            server.active_count.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    } else {
        server.active_count.fetch_add(1, Ordering::Relaxed);
        true
    };
    if !admitted {
        server
            .metrics
            .handshake_failures
            .with_label_values(&["capacity"])
            .inc();
        warn!(peer = %peer, "rejecting at capacity");
        let _ = write_503(stream).await;
        return;
    }
    let active_guard = ActiveGuard {
        counter: server.active_count.clone(),
    };

    // Per-source-IP cap. Defends against a single attacker filling the global
    // cap with half-open handshakes. The guard is held for the duration of the
    // connection (handshake + tunnel).
    // Normalize IPv4-mapped-v6 (`::ffff:1.2.3.4`) to its v4 form before the
    // per-IP cap check. Without this, an attacker dialing the same v4 address
    // via dual-stack and direct paths counts as two distinct keys, halving the
    // cap's effectiveness.
    let mut per_ip_addr = peer.ip();
    if let std::net::IpAddr::V6(v6) = per_ip_addr {
        if let Some(v4) = v6.to_ipv4_mapped() {
            per_ip_addr = std::net::IpAddr::V4(v4);
        }
    }
    let per_ip_guard = match try_acquire_per_ip(&server, per_ip_addr) {
        Some(g) => g,
        None => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["per_ip_capacity"])
                .inc();
            warn!(peer = %peer, "rejecting per-IP capacity");
            drop(active_guard);
            let _ = write_503(stream).await;
            return;
        }
    };

    // PROXY-protocol parsing (optional). Replaces `peer` with the real client.
    // The `peer.ip()` argument is checked against `proxy_protocol_trusted_cidrs`
    // — connections from untrusted peers are rejected before parsing, closing
    // the source-IP-spoof primitive.
    let effective_peer = match proxy_protocol::process(
        &mut stream,
        server.cfg.proxy_protocol,
        peer,
        &server.cfg.proxy_protocol_trusted_cidrs,
    )
    .await
    {
        Ok(ProxyOutcome::Replaced(addr)) => addr,
        Ok(ProxyOutcome::Untouched) => peer,
        Ok(ProxyOutcome::Reject(reason)) => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            warn!(peer = %peer, "PROXY-protocol reject: {reason}");
            drop(per_ip_guard);
            drop(active_guard);
            return;
        }
        Err(e) => {
            warn!(peer = %peer, "PROXY-protocol IO error: {e}");
            drop(per_ip_guard);
            drop(active_guard);
            return;
        }
    };

    // TLS accept itself gets a tighter deadline (5s); subsequent HTTP read uses
    // hyper's builder-level header_read_timeout.
    let tls_deadline = std::time::Duration::from_secs(5);
    let conn_guards = ConnGuards {
        active: active_guard,
        per_ip: per_ip_guard,
    };

    let result = if let Some(acceptor) = &server.tls {
        match tokio::time::timeout(tls_deadline, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => {
                serve_http(server.clone(), tls_stream, effective_peer, conn_guards).await
            }
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
        serve_http(server.clone(), stream, effective_peer, conn_guards).await
    };

    if let Err(e) = result {
        debug!("connection finished with error: {e}");
    }
}

/// Lifetime-bound bundle of per-connection guards. Held by the upgrade future
/// (and therefore the tunnel) so capacity counters reflect *active tunnels*,
/// not just in-flight handshakes. The fields are never read directly — both
/// guards do their work in `Drop`.
#[allow(dead_code)]
pub(crate) struct ConnGuards {
    pub active: ActiveGuard,
    pub per_ip: PerIpGuard,
}

pub(crate) struct ActiveGuard {
    counter: Arc<std::sync::atomic::AtomicU64>,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
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

async fn serve_http<S>(
    server: Arc<Server>,
    stream: S,
    peer: SocketAddr,
    guards: ConnGuards,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let io = TokioIo::new(stream);
    let server_for_svc = server.clone();
    let metrics = server.metrics.clone();
    // The HTTP layer typically handles a single request before upgrading. Wrap
    // the guards in a shared `Mutex<Option<...>>` so `handle_request` can take
    // them on the upgrade path; on a 4xx reject path the guards drop here.
    let guard_slot = Arc::new(std::sync::Mutex::new(Some(guards)));
    let guard_for_svc = guard_slot.clone();
    let svc = service_fn(move |req| {
        let server = server_for_svc.clone();
        let guard_slot = guard_for_svc.clone();
        Box::pin(async move { handle_request(server, peer, req, guard_slot).await })
            as Pin<Box<dyn Future<Output = _> + Send>>
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS));
    // We do NOT disable keep-alive at the builder level: hyper would then
    // emit `Connection: close` on the 101 Switching Protocols response,
    // which conflicts with `Connection: upgrade` and breaks the WS
    // handshake (fastwebsockets reports "invalid connection header").
    // Instead, every non-101 response from `text_resp` carries an explicit
    // `Connection: close` header — see `text_resp` below — so 4xx replies
    // always tear down the TCP connection. This shuts down auth-probe
    // pipelining without breaking the upgrade path. For the upgrade path
    // itself, hyper hands the underlying I/O off after 101 and never re-uses
    // the connection for another HTTP request.

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
    // Any guards still in the slot (4xx paths) drop here.
    Ok(())
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

async fn handle_request(
    server: Arc<Server>,
    peer: SocketAddr,
    mut req: Request<Incoming>,
    guard_slot: Arc<std::sync::Mutex<Option<ConnGuards>>>,
) -> Result<Response<BoxBody>, std::io::Error> {
    if req.uri().path() != server.cfg.ws_path.as_str() {
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
    // Borrow rather than clone — this runs once per HTTP request on the auth
    // hot path. Any owned strings we need below are extracted explicitly.
    let headers = req.headers();

    // Defense-in-depth: reject duplicate occurrences of any auth/routing-relevant
    // header. RFC 7230 §3.2.2 forbids multi-value here for non-list-tokens, and
    // a buggy upstream could otherwise let an attacker shadow the LB-set value.
    for h in [
        "X-Auth-Token",
        "X-Auth-Type",
        "X-Route-Address",
        "X-Route-Port",
    ] {
        if headers.get_all(h).iter().count() > 1 {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "duplicate auth token"));
        }
    }

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

    // Canonical decimal only: the route_set lookup compares against
    // "{addr}:{u16-display}", so accepting "+0" / "00080" / " 80" would let a
    // peer sneak past route allowlists by submitting a non-canonical port that
    // u16::from_str() happens to accept. Require the input to round-trip.
    let port_num: u16 = match route_port.parse::<u16>() {
        Ok(p) if route_port == p.to_string() => p,
        _ => {
            server
                .metrics
                .handshake_failures
                .with_label_values(&["bad_request"])
                .inc();
            return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
        }
    };

    let route_string = format!("{route_address}:{port_num}");

    // CLIENT_IP_HEADER is honored ONLY when the direct peer is in an explicitly
    // trusted CIDR (`CLIENT_IP_HEADER_TRUSTED_CIDRS`). The "empty allowlist →
    // trust anyway" branch was removed — `init_shared` now bails at startup
    // when a header is configured without a CIDR allowlist (auth-bypass close).
    let header_trusted = !server.cfg.client_ip_header_trusted_cidrs.is_empty()
        && server
            .cfg
            .client_ip_header_trusted_cidrs
            .iter()
            .any(|net| net.contains(&peer.ip()));
    // Resolve client IP as `IpAddr` directly: pre-parsing here lets us reject
    // bracketed forms like "[::1]:1234" with a clean BAD_REQUEST instead of a
    // silent auth miss further down.
    let client_ip: std::net::IpAddr = if let Some(h) = &server.cfg.client_ip_header {
        if header_trusted {
            let raw = headers
                .get(h.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            match raw.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    server
                        .metrics
                        .handshake_failures
                        .with_label_values(&["bad_request"])
                        .inc();
                    return Ok(text_resp(StatusCode::BAD_REQUEST, "bad request"));
                }
            }
        } else {
            // Header configured but direct peer not in trusted CIDRs — ignore the
            // header and use the direct peer IP. Bump a metric so operators can
            // spot misconfig.
            server
                .metrics
                .protocol_violations
                .with_label_values(&["client_ip_header_untrusted"])
                .inc();
            peer.ip()
        }
    } else {
        peer.ip()
    };

    // ── Auth ──────────────────────────────────────────────────────────────
    // Lookup is keyed on BLAKE3(token), so the HashMap probe never sees the
    // raw token bytes — the bucket-walk timing channel collapses to "this
    // 32-byte preimage-resistant hash exists or not".
    use streamsockets_auth::token_hash;
    use subtle::{Choice, ConstantTimeEq};
    let snap = server.auth.snapshot_arc();
    let token_h = token_hash(token.as_bytes());
    let cache_opt = snap.by_token_hash.get(&token_h).cloned();
    let cache = match cache_opt {
        Some(c) => {
            // Defense-in-depth: constant-time len + bytes compare with no
            // early exit. ct_eq on slices of differing length returns
            // Choice(0) without comparing bytes; the explicit length Choice
            // guards correctness.
            let stored = c.account.token.as_bytes();
            let cand = token.as_bytes();
            let len_eq: Choice = (stored.len() as u64).ct_eq(&(cand.len() as u64));
            let bytes_eq: Choice = stored.ct_eq(cand);
            if bool::from(len_eq & bytes_eq) {
                c
            } else {
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
        }
        None => {
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
    let allowed = cache.allowed_cidrs.iter().any(|n| n.contains(&client_ip));
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

    // RFC 6455 §4.2.2: server picks exactly one subprotocol. We echo only the
    // literal "streamsockets.v2" — never the entire Sec-WebSocket-Protocol header
    // value (which could include attacker-supplied tokens).
    let want_subprotocol = headers
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.split(',').any(|p| p.trim() == "streamsockets.v2"));

    // Capture whether the client included an explicit X-StreamSockets-Version
    // header before we hand `req` to the upgrade routine (which needs a mut
    // borrow). Per MIGRATION.md §5.1 the server only echoes the version
    // header when the request carried one.
    let echo_version = headers.get("X-StreamSockets-Version").is_some();

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

    if want_subprotocol {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("streamsockets.v2"),
        );
    }
    if echo_version {
        response
            .headers_mut()
            .insert("X-StreamSockets-Version", HeaderValue::from_static("2"));
    }

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

    // Take the connection guards (active count + per-IP) out of the slot and
    // hand them into the tunnel future so capacity reflects active *tunnels*
    // — not just in-flight handshakes that already completed.
    let conn_guards = guard_slot.lock().expect("guard slot mutex").take();

    tokio::spawn(async move {
        // Hold the connection guards for the lifetime of the upgrade + tunnel.
        // They drop here on every exit path, restoring capacity. The
        // `#[allow]` silences clippy's underscore-binding lint — the binding
        // is intentional: we want the guards to live until the future ends,
        // not until the next statement.
        #[allow(clippy::no_effect_underscore_binding)]
        let _conn_guards = conn_guards;

        // Bound the upgrade future — a stalled client otherwise pins this task
        // until TCP keepalive fires (~ minutes).
        let upgraded = match tokio::time::timeout(UPGRADE_TIMEOUT, fut).await {
            Ok(Ok(ws)) => ws,
            Ok(Err(e)) => {
                warn!(account = %account_name, "ws upgrade future failed: {e}");
                server_for_tunnel
                    .metrics
                    .handshake_failures
                    .with_label_values(&["upgrade_failed"])
                    .inc();
                drop(lease);
                return;
            }
            Err(_) => {
                warn!(account = %account_name, "ws upgrade future timed out");
                server_for_tunnel
                    .metrics
                    .handshake_failures
                    .with_label_values(&["upgrade_timeout"])
                    .inc();
                drop(lease);
                return;
            }
        };

        // Record connection start only when the upgrade actually succeeded.
        // This keeps `streamsockets_active_connections` consistent — we
        // increment and decrement under the same condition.
        server_for_tunnel
            .metrics
            .record_connection_start(&account_name);
        let started = std::time::Instant::now();
        let res = tunnel::run_tunnel(
            server_for_tunnel.clone(),
            upgraded,
            route_address,
            port_num,
            max_frame,
            account_name.clone(),
            client_ip.to_string(),
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
    // `Connection: close` is defense-in-depth — even with `keep_alive(false)`
    // on the builder, signaling close to misbehaving clients prevents pipelined
    // auth probes against the same TCP connection.
    Response::builder()
        .status(status)
        .header("Connection", "close")
        .body(body)
        .expect("text_resp inputs are static and always valid")
}

fn empty_body() -> BoxBody {
    use http_body_util::BodyExt;
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
