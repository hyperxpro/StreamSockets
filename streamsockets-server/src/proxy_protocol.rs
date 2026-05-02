//! PROXY-protocol v1/v2 parser. Returns the *real* client SocketAddr when the
//! header is present (after stripping the bytes from the wire).
//!
//! Modes (`PROXY_PROTOCOL` env):
//! * `disabled` — never parse. (default)
//! * `v1` / `v2` — require the header; reject the connection if absent.
//! * `optional` — parse if present, fall through if not.
//!
//! In every non-disabled mode the direct TCP peer must be in
//! `PROXY_PROTOCOL_TRUSTED_CIDRS` — otherwise the connection is rejected
//! before we read a byte. Without this gate, any reachable peer can forge a
//! PROXY header to spoof the source IP and bypass `allowedIps` checks.
//!
//! AF_UNSPEC / `LOCAL` (LB health probes) is honored as if the header were
//! absent (`Untouched`) per RFC: we keep the direct peer address and let the
//! connection proceed.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use ppp::{HeaderResult, PartialResult};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::ProxyProtocolMode;

const PROXY_V1_PREAMBLE: &[u8] = b"PROXY ";
const PROXY_V2_PREAMBLE: &[u8; 12] = &[
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Result of a peek+parse cycle.
pub enum ProxyOutcome {
    /// PROXY header consumed; this is the real client address.
    Replaced(SocketAddr),
    /// PROXY header was absent (or LOCAL); original peer address still applies.
    Untouched,
    /// PROXY header was malformed or required-but-missing → drop the connection.
    Reject(String),
}

/// PROXY v2 allows up to 65535 bytes of TLVs (length is u16 BE). 4 KiB
/// comfortably accommodates real-world LB headers (AWS VPCE TLVs, ALPN, etc.)
/// without exposing us to a 64 KiB-per-connection memory amplification.
const MAX_HEADER_BYTES: usize = 4096;
/// Total wallclock deadline for the PROXY peek+read cycle. Slowloris bound.
const PEEK_DEADLINE: Duration = Duration::from_millis(500);

/// Inspect the head of `stream` without consuming. If a PROXY header is present,
/// `read_exact` it off so hyper sees a clean wire.
///
/// `trusted_peer_cidrs` is the allowlist of LB IPs permitted to send a PROXY
/// header. When non-empty and the direct peer falls outside, this function
/// returns `Reject` immediately.
pub async fn process(
    stream: &mut TcpStream,
    mode: ProxyProtocolMode,
    fallback: SocketAddr,
    trusted_peer_cidrs: &[ipnet::IpNet],
) -> io::Result<ProxyOutcome> {
    if matches!(mode, ProxyProtocolMode::Disabled) {
        return Ok(ProxyOutcome::Untouched);
    }

    // Trust gate: refuse to parse a PROXY header from a peer that isn't a
    // configured LB. Without this, any reachable peer can spoof source IP.
    let peer_ip = fallback.ip();
    let trusted = trusted_peer_cidrs.iter().any(|n| n.contains(&peer_ip));
    if !trusted {
        return Ok(ProxyOutcome::Reject(format!(
            "PROXY header from untrusted peer {peer_ip}"
        )));
    }

    let deadline = tokio::time::Instant::now() + PEEK_DEADLINE;
    let mut buf = [0u8; MAX_HEADER_BYTES];
    let mut last_peeked: usize = 0;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(ProxyOutcome::Reject("PROXY peek timed out".into()));
        }
        let n = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(ProxyOutcome::Reject("peek deadline".into())),
        };
        if n == 0 {
            return Ok(ProxyOutcome::Reject("EOF before PROXY header".into()));
        }
        let peeked = n;
        // CPU-spin guard: `tokio::TcpStream::peek` does not block waiting for
        // *new* data — it returns whatever is already in the kernel buffer.
        // Combined with `readable()` (which stays Ready as long as ANY bytes
        // are buffered, regardless of whether they're new), a slow peer that
        // dribbles a partial PROXY header would let us spin at ~µs per iter
        // until the 500 ms deadline. When `peek` returned the same number of
        // bytes as last time, we know no progress was made; sleep briefly so
        // the slowloris cost is at most ~100 iterations × 5 ms = 500 ms.
        if peeked > 0 && peeked == last_peeked {
            let nap =
                tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_millis(5));
            tokio::pin!(nap);
            tokio::select! {
                _ = &mut nap => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Ok(ProxyOutcome::Reject("PROXY peek timed out".into()));
                }
            }
        }

        // Quick early-out for "definitely not PROXY" — saves more peek loops.
        if peeked >= 12 {
            let v2 = buf[..12] == *PROXY_V2_PREAMBLE;
            let v1 = buf[..6] == *PROXY_V1_PREAMBLE;
            if !v1 && !v2 {
                return match mode {
                    ProxyProtocolMode::Optional => Ok(ProxyOutcome::Untouched),
                    _ => Ok(ProxyOutcome::Reject("missing PROXY preamble".into())),
                };
            }
        }

        let parsed = HeaderResult::parse(&buf[..peeked]);
        if parsed.is_incomplete() {
            if peeked >= MAX_HEADER_BYTES {
                return Ok(ProxyOutcome::Reject("PROXY header oversized".into()));
            }
            last_peeked = peeked;
            continue;
        }
        match parsed {
            HeaderResult::V1(Ok(hdr)) => {
                let consumed = hdr.header.len();
                let outcome = v1_outcome(&hdr.addresses, fallback);
                match tokio::time::timeout_at(deadline, consume(stream, consumed)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Ok(ProxyOutcome::Reject("consume deadline".into())),
                }
                return Ok(outcome);
            }
            HeaderResult::V2(Ok(hdr)) => {
                let consumed = hdr.header.len();
                let outcome = v2_outcome(&hdr, fallback);
                match tokio::time::timeout_at(deadline, consume(stream, consumed)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Ok(ProxyOutcome::Reject("consume deadline".into())),
                }
                return Ok(outcome);
            }
            HeaderResult::V1(Err(e)) => return Ok(ProxyOutcome::Reject(format!("v1 parse: {e}"))),
            HeaderResult::V2(Err(e)) => return Ok(ProxyOutcome::Reject(format!("v2 parse: {e}"))),
        }
    }
}

fn v1_outcome(addrs: &ppp::v1::Addresses, fallback: SocketAddr) -> ProxyOutcome {
    match addrs {
        ppp::v1::Addresses::Tcp4(a) => ProxyOutcome::Replaced(SocketAddr::new(
            std::net::IpAddr::V4(a.source_address),
            a.source_port,
        )),
        ppp::v1::Addresses::Tcp6(a) => ProxyOutcome::Replaced(SocketAddr::new(
            std::net::IpAddr::V6(a.source_address),
            a.source_port,
        )),
        // PROXY v1 "UNKNOWN" — keep the direct peer (LB health probe).
        ppp::v1::Addresses::Unknown => {
            let _ = fallback;
            ProxyOutcome::Untouched
        }
    }
}

fn v2_outcome(hdr: &ppp::v2::Header<'_>, fallback: SocketAddr) -> ProxyOutcome {
    use ppp::v2::Command;
    // RFC: LOCAL command (health probes) MUST be processed as if the header
    // were absent. Without this, LBs see 401/403 and mark the backend down.
    if matches!(hdr.command, Command::Local) {
        let _ = fallback;
        return ProxyOutcome::Untouched;
    }
    match &hdr.addresses {
        ppp::v2::Addresses::IPv4(a) => ProxyOutcome::Replaced(SocketAddr::new(
            std::net::IpAddr::V4(a.source_address),
            a.source_port,
        )),
        ppp::v2::Addresses::IPv6(a) => ProxyOutcome::Replaced(SocketAddr::new(
            std::net::IpAddr::V6(a.source_address),
            a.source_port,
        )),
        // AF_UNSPEC / Unix sockets — fall through.
        _ => {
            let _ = fallback;
            ProxyOutcome::Untouched
        }
    }
}

async fn consume(stream: &mut TcpStream, n: usize) -> io::Result<()> {
    // Stack buffer in chunks — avoid the per-connection heap allocation.
    let mut scratch = [0u8; 1024];
    let mut remaining = n;
    while remaining > 0 {
        let take = remaining.min(scratch.len());
        stream.read_exact(&mut scratch[..take]).await?;
        remaining -= take;
    }
    Ok(())
}
