//! PROXY-protocol v1/v2 parser. Returns the *real* client SocketAddr when the
//! header is present (after stripping the bytes from the wire).
//!
//! Modes (`PROXY_PROTOCOL` env):
//! * `disabled` — never parse. (default)
//! * `v1` / `v2` — require the header; reject the connection if absent.
//! * `optional` — parse if present, fall through if not. Risky if the LB doesn't
//!   strip an attacker-supplied PROXY header — only enable for trusted networks.

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
    /// PROXY header was absent; original peer address still applies.
    Untouched,
    /// PROXY header was malformed or required-but-missing → drop the connection.
    Reject(String),
}

const MAX_HEADER_BYTES: usize = 536;

/// Inspect the head of `stream` without consuming. If a PROXY header is present,
/// `read_exact` it off so hyper sees a clean wire.
pub async fn process(
    stream: &mut TcpStream,
    mode: ProxyProtocolMode,
    fallback: SocketAddr,
) -> io::Result<ProxyOutcome> {
    if matches!(mode, ProxyProtocolMode::Disabled) {
        return Ok(ProxyOutcome::Untouched);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut buf = [0u8; MAX_HEADER_BYTES];
    let mut peeked;

    // Grow peek buffer until parser succeeds or we conclude the header is absent.
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(ProxyOutcome::Reject("PROXY peek timed out".into()));
        }
        // peek() returns whatever the kernel currently has; loop until enough.
        let n = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(ProxyOutcome::Reject("peek deadline".into())),
        };
        if n == 0 {
            return Ok(ProxyOutcome::Reject("EOF before PROXY header".into()));
        }
        peeked = n;

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
            tokio::time::sleep(Duration::from_millis(2)).await;
            continue;
        }
        match parsed {
            HeaderResult::V1(Ok(hdr)) => {
                let consumed = hdr.header.len();
                let addr = v1_addr(&hdr.addresses, fallback);
                consume(stream, consumed).await?;
                return Ok(ProxyOutcome::Replaced(addr));
            }
            HeaderResult::V2(Ok(hdr)) => {
                let consumed = hdr.header.len();
                let addr = v2_addr(&hdr.addresses, fallback);
                consume(stream, consumed).await?;
                return Ok(ProxyOutcome::Replaced(addr));
            }
            HeaderResult::V1(Err(e)) => return Ok(ProxyOutcome::Reject(format!("v1 parse: {e}"))),
            HeaderResult::V2(Err(e)) => return Ok(ProxyOutcome::Reject(format!("v2 parse: {e}"))),
        }
    }
}

fn v1_addr(addrs: &ppp::v1::Addresses, fallback: SocketAddr) -> SocketAddr {
    match addrs {
        ppp::v1::Addresses::Tcp4(a) => {
            SocketAddr::new(std::net::IpAddr::V4(a.source_address), a.source_port)
        }
        ppp::v1::Addresses::Tcp6(a) => {
            SocketAddr::new(std::net::IpAddr::V6(a.source_address), a.source_port)
        }
        ppp::v1::Addresses::Unknown => fallback,
    }
}

fn v2_addr(addrs: &ppp::v2::Addresses, fallback: SocketAddr) -> SocketAddr {
    match addrs {
        ppp::v2::Addresses::IPv4(a) => {
            SocketAddr::new(std::net::IpAddr::V4(a.source_address), a.source_port)
        }
        ppp::v2::Addresses::IPv6(a) => {
            SocketAddr::new(std::net::IpAddr::V6(a.source_address), a.source_port)
        }
        _ => fallback,
    }
}

async fn consume(stream: &mut TcpStream, n: usize) -> io::Result<()> {
    let mut throwaway = vec![0u8; n];
    stream.read_exact(&mut throwaway).await?;
    Ok(())
}
