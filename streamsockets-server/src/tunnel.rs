//! Bidirectional WebSocket ↔ UDP forwarder.
//!
//! Mirrors `server/WebSocketServerHandler.java` + `DownstreamHandler.java`
//! per MIGRATION.md §7.1.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::Server;

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
    ws.set_max_message_size(max_frame * 2);
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    ws.set_writev(false);

    // Resolve DNS post-handshake via the system resolver (getaddrinfo).
    let upstream: SocketAddr = match resolve(&address, port).await {
        Ok(addr) => addr,
        Err(e) => {
            server.metrics.upstream_dns_failures.inc();
            warn!(account = %account, client_ip = %client_ip, route = %format!("{address}:{port}"), "dns fail: {e}");
            let _ = ws
                .write_frame(Frame::close(
                    1011,
                    format!("dns: {address}: {e}").as_bytes(),
                ))
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
                .write_frame(Frame::close(
                    1011,
                    format!("connect: {upstream}: {e}").as_bytes(),
                ))
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
    let max_frame_clone = max_frame;
    let udp_recv = udp.clone();
    let m = server.metrics.clone();
    let account_recv = account.clone();
    let shutdown = server.shutdown.clone();

    // upstream-to-ws task: read UDP, send to WS via channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(256);

    tokio::spawn(async move {
        let mut buf = vec![0u8; max_frame_clone];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                r = udp_recv.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            if n == 0 { continue; }
                            m.record_bytes_sent(&account_recv, n as u64);
                            let payload = bytes::Bytes::copy_from_slice(&buf[..n]);
                            if tx.send(payload).await.is_err() { break; }
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
    let close_reason: Option<u16>;
    let shutdown = server.shutdown.clone();
    let force_close = server.force_close.clone();
    let grace_secs = server.cfg.shutdown_grace_seconds;
    let mut sent_going_away = false;
    // drain_grace starts armed far in the future; we reset it when shutdown fires.
    let drain_grace = tokio::time::sleep(std::time::Duration::from_secs(86_400 * 365));
    tokio::pin!(drain_grace);

    loop {
        tokio::select! {
            // Server is shutting down (first SIGTERM): send 1001 once, arm drain timer.
            _ = shutdown.cancelled(), if !sent_going_away => {
                let _ = ws.write_frame(Frame::close(1001, b"server going away")).await;
                sent_going_away = true;
                drain_grace.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(grace_secs));
                debug!(account = %account, grace = grace_secs, "sent 1001 on SIGTERM; draining");
            }
            // After grace, hard-close with 1012 (Service Restart).
            _ = &mut drain_grace, if sent_going_away => {
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
            // bytes from upstream → WS
            maybe = rx.recv() => {
                match maybe {
                    Some(payload) => {
                        let frame = Frame::binary(Payload::Owned(payload.to_vec()));
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
                            let bytes = frame.payload.to_owned();
                            server.metrics.record_bytes_received(&account, bytes.len() as u64);
                            if let Err(e) = udp.send(&bytes).await {
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
                            // Try to parse the client's close code from the frame payload.
                            let payload = frame.payload.as_ref();
                            let code = if payload.len() >= 2 {
                                u16::from_be_bytes([payload[0], payload[1]])
                            } else {
                                1005
                            };
                            close_reason = Some(code);
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
                        // Map RSV / unknown opcode / frame format errors to 1002 per spec §5.3.
                        debug!("ws read err: {e}");
                        let s = e.to_string();
                        let is_protocol = s.contains("RSV")
                            || s.contains("opcode")
                            || s.contains("Reserved")
                            || s.contains("Frame format");
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
