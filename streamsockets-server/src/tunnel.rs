//! Bidirectional WebSocket ↔ UDP forwarder.
//!
//! Mirrors `server/WebSocketServerHandler.java` + `DownstreamHandler.java`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::BytesMut;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::net::UdpSocket;
use tokio::time::Sleep;
use tracing::{debug, warn};

use crate::Server;

/// Cap upstream DNS resolution to bound tunnel start-up latency. Without this,
/// a stalled resolver pins the tunnel future indefinitely.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Server-side ping cadence. Idle UDP tunnels behind stateful firewalls go
/// dead at the firewall's idle timeout (typically 30–60 s); we ping at half
/// that to keep the path warm and detect a half-open client.
const SERVER_PING_INTERVAL: Duration = Duration::from_secs(30);
/// Hard-cap on the close-handshake drain. After we send Close we wait this
/// long for the peer's mirrored Close before tearing down TCP.
const CLOSE_DRAIN: Duration = Duration::from_secs(1);

/// Run a tunnel until either side terminates.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel(
    server: Arc<Server>,
    ws: fastwebsockets::WebSocket<TokioIo<Upgraded>>,
    address: String,
    port: u16,
    max_frame: usize,
    account: String,
    client_ip: String,
    tunnel_id: uuid::Uuid,
) -> anyhow::Result<()> {
    server.metrics.active_tunnels.inc();
    let _tunnel_guard = ActiveTunnelGuard {
        m: server.metrics.clone(),
    };

    let mut ws = ws;
    // Continuation reassembly bounded at MAX_FRAME_SIZE × 2 to bound
    // slow-loris fragmentation. Defaults to 65536 × 2 = 131072.
    ws.set_max_message_size(max_frame.saturating_mul(2));
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    ws.set_writev(false);

    // Resolve DNS post-handshake via the system resolver (getaddrinfo), bounded
    // by `DNS_TIMEOUT`. Errors close the tunnel with a sanitized reason —
    // never echo the resolver's text back to the peer (info leak + RFC 6455
    // 123-byte cap).
    let upstream: SocketAddr = match tokio::time::timeout(DNS_TIMEOUT, resolve(&address, port))
        .await
    {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            server.metrics.upstream_dns_failures.inc();
            warn!(account = %account, client_ip = %client_ip, route = %format!("{address}:{port}"), "dns fail: {e}");
            let _ = ws
                .write_frame(Frame::close(1011, b"upstream unavailable"))
                .await;
            return Ok(());
        }
        Err(_) => {
            server.metrics.upstream_dns_failures.inc();
            warn!(account = %account, client_ip = %client_ip, route = %format!("{address}:{port}"), "dns timeout");
            let _ = ws
                .write_frame(Frame::close(1011, b"upstream unavailable"))
                .await;
            return Ok(());
        }
    };

    // Bind + connect UDP egress with verified buffer sizes.
    let udp = match build_udp(upstream).await {
        Ok(u) => u,
        Err(e) => {
            server.metrics.upstream_connect_failures.inc();
            warn!(account = %account, client_ip = %client_ip, "udp connect fail: {e}");
            let _ = ws
                .write_frame(Frame::close(1011, b"upstream unavailable"))
                .await;
            return Ok(());
        }
    };

    debug!(
        account = %account,
        client_ip = %client_ip,
        upstream = %upstream,
        tunnel_id = %tunnel_id,
        "tunnel established"
    );

    // We can't split fastwebsockets::WebSocket into reader/writer halves easily,
    // so route both directions through a single task. Use FragmentCollector for cleanly
    // reassembling continuation frames bounded by max_message_size.
    let mut ws = fastwebsockets::FragmentCollector::new(ws);
    let udp = Arc::new(udp);
    let udp_recv = udp.clone();
    let m = server.metrics.clone();
    let account_recv = account.clone();
    let shutdown_recv = server.shutdown.clone();

    // upstream-to-ws task: read UDP, send to WS via channel.
    // Channel carries `BytesMut` so the buffer can be moved into a fastwebsockets
    // `Payload::Bytes(_)` without an additional copy.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<BytesMut>(256);

    // Wrap in JoinSet so the subtask is aborted when the tunnel future returns
    // — the previous detached `tokio::spawn` leaked a task per closed tunnel
    // when the recv was idle.
    let mut subtasks = tokio::task::JoinSet::new();
    let max_frame_clone = max_frame;
    subtasks.spawn(async move {
        let mut buf = vec![0u8; max_frame_clone];
        loop {
            tokio::select! {
                _ = shutdown_recv.cancelled() => break,
                r = udp_recv.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            if n == 0 { continue; }
                            // tokio's `recv` doesn't surface MSG_TRUNC; detect
                            // the buffer-fill edge case as a likely truncation.
                            if n == buf.len() {
                                m.upstream_truncated.inc();
                                debug!(
                                    "upstream datagram filled the recv buffer ({} bytes); \
                                     possible truncation. Increase MAX_FRAME_SIZE.",
                                    n
                                );
                            }
                            m.record_bytes_sent(&account_recv, n as u64);
                            let mut owned = BytesMut::with_capacity(n);
                            owned.extend_from_slice(&buf[..n]);
                            // try_send: if the WS side is slow, drop the datagram
                            // and bump a metric rather than blocking the UDP recv
                            // (which would let the kernel buffer fill).
                            match tx.try_send(owned) {
                                Ok(()) => {}
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    // Bounded channel full: the WS-write side is
                                    // slower than the UDP-recv side. This is
                                    // a downstream-consumer drop, distinct from
                                    // an actual UDP-send failure (which is
                                    // counted under `upstream_send_drops`).
                                    m.downstream_queue_drops.inc();
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(e) => {
                            // ICMP unreachable surfaces here on connected sockets.
                            m.upstream_unreachable.inc();
                            debug!("udp recv err: {e}");
                            break;
                        }
                    }
                }
            }
        }
    });

    let mut closed_normally = false;
    let mut received_close_from_client = false;
    // `close_reason` is consumed by the metrics emit after the loop. Each
    // `break` writes to it; the initial `None` documents the invariant
    // (every loop exit assigns) and prevents UB-adjacent garbage if a future
    // edit adds a `break` without assignment. The unused-assignment lint
    // fires because the initial None is dead — silence locally.
    #[allow(unused_assignments)]
    let mut close_reason: Option<u16> = None;
    let shutdown = server.shutdown.clone();
    let force_close = server.force_close.clone();
    let grace_secs = server.cfg.shutdown_grace_seconds;
    let mut sent_going_away = false;
    // drain_grace is unarmed at start. Only armed when GOING_AWAY (1001) is
    // sent on the first SIGTERM; until then, the corresponding `select!` arm
    // is gated by `if let Some(...)`. Using `Option<Pin<Box<Sleep>>>` (vs a
    // `Pending` future) avoids tying up a 365-day timer in the runtime's
    // delay queue for the entire tunnel lifetime.
    let mut drain_grace: Option<Pin<Box<Sleep>>> = None;

    // Periodic ping to keep stateful firewalls warm + detect a half-open peer.
    // ±10 % jitter on the first tick prevents N tunnels that started together
    // from pinging in lockstep and creating a periodic CPU/network spike.
    let jitter_ms: u64 = {
        use rand::Rng;
        let span = SERVER_PING_INTERVAL.as_millis() as u64 / 5; // 20% range
        rand::thread_rng().gen_range(0..=span)
    };
    let first_tick = tokio::time::Instant::now() + SERVER_PING_INTERVAL
        - Duration::from_millis(SERVER_PING_INTERVAL.as_millis() as u64 / 10)
        + Duration::from_millis(jitter_ms);
    let mut ping_iv = tokio::time::interval_at(first_tick, SERVER_PING_INTERVAL);
    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Server is shutting down (first SIGTERM): send 1001 once, arm drain timer.
            _ = shutdown.cancelled(), if !sent_going_away => {
                let _ = ws.write_frame(Frame::close(1001, b"server going away")).await;
                sent_going_away = true;
                drain_grace = Some(Box::pin(tokio::time::sleep(Duration::from_secs(grace_secs))));
                debug!(account = %account, grace = grace_secs, "sent 1001 on SIGTERM; draining");
            }
            // After grace, hard-close with 1012 (Service Restart). Arm only
            // when `drain_grace` is `Some(_)` so we don't block on a phantom
            // future for the entire tunnel lifetime. `select!` only constructs
            // the inner future when the `if` precondition is true.
            _ = poll_optional_sleep(&mut drain_grace), if drain_grace.is_some() => {
                let _ = ws.write_frame(Frame::close(1012, b"service restart")).await;
                close_reason = Some(1012);
                break;
            }
            // Force-close (second SIGTERM): skip remaining grace, send 1012 immediately
            // per spec §6.7. UDP egress is closed last (Drop on `udp` after this loop).
            _ = force_close.cancelled() => {
                let _ = ws.write_frame(Frame::close(1012, b"service restart (forced)")).await;
                close_reason = Some(1012);
                break;
            }
            // Server-initiated ping. Detection of a missed pong is implicit —
            // a half-open peer eventually surfaces as a write error or a TCP
            // keepalive RST; the ping itself just keeps NATs warm.
            _ = ping_iv.tick() => {
                if let Err(e) = ws.write_frame(Frame::new(true, OpCode::Ping, None, Payload::Borrowed(b"ss"))).await {
                    debug!("server ping write err: {e}");
                    close_reason = Some(1011);
                    break;
                }
            }
            // bytes from upstream → WS
            maybe = rx.recv() => {
                match maybe {
                    Some(payload) => {
                        let frame = Frame::binary(Payload::Bytes(payload));
                        if let Err(e) = ws.write_frame(frame).await {
                            debug!("ws write err: {e}");
                            close_reason = Some(1011);
                            break;
                        }
                    }
                    None => { close_reason = Some(1011); break; }
                }
            }
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => match frame.opcode {
                        OpCode::Binary => {
                            let bytes = frame.payload.as_ref();
                            server.metrics.record_bytes_received(&account, bytes.len() as u64);
                            if let Err(e) = udp.send(bytes).await {
                                server.metrics.upstream_send_drops.inc();
                                debug!("udp send err: {e}");
                            }
                        }
                        OpCode::Text => {
                            server.metrics.protocol_violations.with_label_values(&["text_frame"]).inc();
                            warn!(account = %account, "text frame on v2; closing 1003");
                            let _ = ws.write_frame(Frame::close(1003, b"text frames not allowed in v2")).await;
                            close_reason = Some(1003);
                            break;
                        }
                        OpCode::Close => {
                            closed_normally = true;
                            received_close_from_client = true;
                            // Parse + validate the client's close code per RFC 6455 §7.4.
                            // Reserved/forbidden codes (0–999, 1004, 1005, 1006, 1015) are
                            // bucketed as "invalid" rather than echoed into a label.
                            let payload = frame.payload.as_ref();
                            let raw = if payload.len() >= 2 {
                                u16::from_be_bytes([payload[0], payload[1]])
                            } else {
                                1005
                            };
                            close_reason = Some(sanitize_close_code(raw));
                            break;
                        }
                        OpCode::Ping | OpCode::Pong => {
                            // fastwebsockets auto-pong handles ping; pongs we just ignore.
                        }
                        OpCode::Continuation => {
                            // FragmentCollector should reassemble; if we see a raw continuation
                            // here that's a protocol error.
                            server.metrics.protocol_violations.with_label_values(&["continuation"]).inc();
                            close_reason = Some(1002);
                            break;
                        }
                    },
                    Err(WebSocketError::ConnectionClosed) => {
                        closed_normally = true;
                        received_close_from_client = true;
                        close_reason = Some(1006); // Abnormal Closure
                        break;
                    }
                    Err(e) => {
                        // Map RSV / opcode / frame-format / fragmentation errors to
                        // 1002 per RFC 6455 §5.3 — match concrete enum variants
                        // rather than substring-matching `to_string()` (the prior
                        // implementation broke whenever fastwebsockets touched its
                        // Display impls).
                        debug!("ws read err: {e}");
                        let is_protocol = matches!(
                            e,
                            WebSocketError::ReservedBitsNotZero
                                | WebSocketError::ControlFrameFragmented
                                | WebSocketError::PingFrameTooLarge
                                | WebSocketError::FrameTooLarge
                                | WebSocketError::InvalidFragment
                                | WebSocketError::InvalidContinuationFrame
                                | WebSocketError::InvalidUTF8
                                | WebSocketError::InvalidCloseFrame
                                | WebSocketError::InvalidCloseCode
                                | WebSocketError::InvalidStatusCode(_)
                                | WebSocketError::InvalidValue
                        );
                        if is_protocol {
                            server
                                .metrics
                                .protocol_violations
                                .with_label_values(&["frame_format"])
                                .inc();
                            close_reason = Some(1002);
                        } else {
                            close_reason = Some(1011);
                        }
                        break;
                    }
                }
            }
        }
    }

    // Best-effort close drain: if we initiated the Close, give the peer 1s
    // to mirror it before TCP teardown (RFC 6455 §1.4). Skip if the peer
    // already sent Close.
    if !received_close_from_client {
        let _ = tokio::time::timeout(CLOSE_DRAIN, async {
            loop {
                match ws.read_frame().await {
                    Ok(f) if matches!(f.opcode, OpCode::Close) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        })
        .await;
    }

    // JoinSet is dropped here — pending subtasks are aborted, no task leak.
    subtasks.abort_all();
    while subtasks.join_next().await.is_some() {}

    if let Some(code) = close_reason {
        // Spec §13.3 row 11/12: `side="client"` for closes initiated by the
        // client peer (we *received* a close), `side="server"` otherwise.
        let side = if received_close_from_client {
            "client"
        } else {
            "server"
        };
        server
            .metrics
            .ws_close
            .with_label_values(&[side, &code.to_string()])
            .inc();
    }
    if closed_normally {
        debug!(account = %account, "tunnel closed normally");
    }
    Ok(())
}

/// RFC 6455 §7.4: codes 0-999, 1004, 1005, 1006, 1015 are reserved/forbidden
/// on the wire. Bucket invalid codes as a single sentinel so high-cardinality
/// label explosions are impossible.
fn sanitize_close_code(code: u16) -> u16 {
    match code {
        // Allowed standard codes
        1000..=1003 | 1007..=1014 if code != 1004 => code,
        // Application range (RFC 6455 §7.4.2)
        3000..=4999 => code,
        // Anything else (incl. 0–999, 1004, 1005, 1006, 1015, 5000+) → sentinel.
        _ => 1002,
    }
}

struct ActiveTunnelGuard {
    m: Arc<streamsockets_metrics::Metrics>,
}
impl Drop for ActiveTunnelGuard {
    fn drop(&mut self) {
        self.m.active_tunnels.dec();
    }
}

async fn resolve(address: &str, port: u16) -> anyhow::Result<SocketAddr> {
    // If it's already an IP, skip DNS.
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Prefer IPv4 over IPv6 — upstream peers are overwhelmingly v4-reachable.
    let mut first: Option<SocketAddr> = None;
    for addr in tokio::net::lookup_host((address, port)).await? {
        if addr.is_ipv4() {
            return Ok(addr);
        }
        first.get_or_insert(addr);
    }
    first.ok_or_else(|| anyhow::anyhow!("no records for {address}"))
}

async fn build_udp(upstream: SocketAddr) -> anyhow::Result<UdpSocket> {
    // Constant string parses are infallible; document the invariant explicitly
    // (replaces a bare `.unwrap()` for code-quality lint compliance).
    let bind: SocketAddr = if upstream.is_ipv6() {
        "[::]:0".parse().expect("static IPv6 wildcard literal")
    } else {
        "0.0.0.0:0".parse().expect("static IPv4 wildcard literal")
    };
    let sock = socket2::Socket::new(
        if upstream.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("creating udp socket")?;
    sock.set_nonblocking(true)?;

    let target_buf_bytes: usize = 4 * 1024 * 1024;
    let _ = sock.set_recv_buffer_size(target_buf_bytes);
    let _ = sock.set_send_buffer_size(target_buf_bytes);

    // IP_BIND_ADDRESS_NO_PORT (Linux ≥ 4.2): defer ephemeral-port allocation to
    // connect() instead of bind(). Allows the same local port to be reused for
    // distinct (local, remote) 4-tuples — eliminates port exhaustion on hosts
    // creating thousands of egress UDP sockets per second.
    #[cfg(target_os = "linux")]
    if !upstream.is_ipv6() {
        use std::os::fd::AsRawFd;
        const IP_BIND_ADDRESS_NO_PORT: libc::c_int = 24;
        let v: libc::c_int = 1;
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_BIND_ADDRESS_NO_PORT,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            tracing::debug!(
                "IP_BIND_ADDRESS_NO_PORT setsockopt failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    sock.bind(&bind.into()).context("binding udp")?;

    // Realise the buffers via getsockopt and warn if the kernel capped them.
    // Linux returns 2× the requested value (kernel-doubled) — we record the
    // realised value so operators can sanity-check `sysctl net.core.rmem_max`.
    if let (Ok(rcv), Ok(snd)) = (sock.recv_buffer_size(), sock.send_buffer_size()) {
        let metrics = streamsockets_metrics::Metrics::global();
        metrics
            .udp_egress_socket_buffer_bytes
            .with_label_values(&["recv"])
            .set(rcv as f64);
        metrics
            .udp_egress_socket_buffer_bytes
            .with_label_values(&["send"])
            .set(snd as f64);
        // The kernel doubles the requested size; warn if we're far below 2× target.
        if rcv < target_buf_bytes {
            tracing::warn!(
                requested = target_buf_bytes,
                realised = rcv,
                "SO_RCVBUF below requested; consider raising net.core.rmem_max"
            );
        }
        if snd < target_buf_bytes {
            tracing::warn!(
                requested = target_buf_bytes,
                realised = snd,
                "SO_SNDBUF below requested; consider raising net.core.wmem_max"
            );
        }
    }

    let std_sock: std::net::UdpSocket = sock.into();
    let udp = UdpSocket::from_std(std_sock)?;
    udp.connect(upstream).await.context("connecting udp")?;
    Ok(udp)
}

/// Poll an `Option<Pin<Box<Sleep>>>` from inside a `select!` arm. The `if`
/// precondition gates whether we ever enter this branch; the inner `match`
/// turns "None" into a never-completing future, which the caller's `if` will
/// have prevented anyway. The branch is only awaited when `Some`.
async fn poll_optional_sleep(s: &mut Option<std::pin::Pin<Box<tokio::time::Sleep>>>) {
    match s {
        Some(s) => s.as_mut().await,
        None => std::future::pending::<()>().await,
    }
}
