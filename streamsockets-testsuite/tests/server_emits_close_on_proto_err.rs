//! Verifies FIX.md §3.1.4: on a protocol-class read error the server now
//! writes an explicit `Close(1002, "protocol error")` frame to the peer
//! before tearing down TCP. Previously the server set `close_reason =
//! Some(1002)` and `break`ed without writing a Close frame; the client
//! observed TCP EOF and classified the disconnect as Transient, which made
//! correlating the server-side metric to the client-side log harder.
//!
//! Test strategy:
//!   1. Spawn the real server with the standard test config.
//!   2. Hand-roll a v2 WebSocket handshake on a raw `TcpStream`.
//!   3. Write a deliberately malformed frame (`[0xC0, 0x00]`,
//!      FIN=1 RSV1=1) so the server's `WebSocketError::ReservedBitsNotZero`
//!      branch fires.
//!   4. Read the next bytes from the socket and assert they decode to a
//!      Close opcode frame carrying code 1002.

mod common;

use std::time::Duration;

use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn server_writes_close_1002_on_protocol_error() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;
    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    let mut stream = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    let req = format!(
        "GET /tunnel HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: streamsockets.v2\r\n\
         X-Auth-Type: Token\r\n\
         X-Auth-Token: secret-token\r\n\
         X-Route-Address: 127.0.0.1\r\n\
         X-Route-Port: {upstream}\r\n\
         X-StreamSockets-Version: 2\r\n\
         \r\n",
        port = server_port,
        key = key_b64,
        upstream = echo_port,
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    // Read until we see the end of the HTTP response headers.
    let mut response = Vec::new();
    let mut tmp = [0u8; 1024];
    let read_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        assert!(
            std::time::Instant::now() <= read_deadline,
            "timeout waiting for 101 response; got: {response:?}"
        );
        let n = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut tmp))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n == 0 {
            // No more bytes yet; keep polling.
            continue;
        }
        response.extend_from_slice(&tmp[..n]);
    }
    let head = String::from_utf8_lossy(&response);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols; got: {head}"
    );
    // Verify Sec-WebSocket-Accept matches expectations (sanity check that
    // we drove the handshake correctly). Header names are case-insensitive
    // and hyper emits them lowercased; compare on the lowercased response.
    let expected_accept = sec_websocket_accept(&key_b64);
    let head_lc = head.to_ascii_lowercase();
    let needle = format!("sec-websocket-accept: {expected_accept}").to_ascii_lowercase();
    assert!(
        head_lc.contains(&needle),
        "missing Sec-WebSocket-Accept header in response: {head}"
    );

    // Any extra bytes after the headers belong to the upgraded protocol.
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let extra = response[header_end..].to_vec();

    // Write a malformed frame: FIN=1, RSV1=1 (illegal), opcode=0,
    // MASK=1, payload_len=0, mask key all zeros. Client-to-server frames
    // MUST be masked per RFC 6455 §5.3 — without MASK=1 the server's
    // fastwebsockets refuses the frame for a different reason
    // (UnmaskedFrameFromClient is a fastwebsockets variant). We *want* the
    // RSV-bit refusal so the variant label is `reserved_bits_not_zero`.
    let bad: [u8; 6] = [0xC0, 0x80, 0x00, 0x00, 0x00, 0x00];
    stream.write_all(&bad).await.unwrap();
    stream.flush().await.unwrap();

    // Read the server's response: should be a Close opcode frame with code 1002.
    let mut buf = extra;
    let read_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < read_deadline {
        let mut tmp = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut tmp))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if n > 0 {
            buf.extend_from_slice(&tmp[..n]);
        }
        // A server Close frame: [0x88, len, code_hi, code_lo, ...reason]
        if buf.len() >= 4 && (buf[0] & 0x0f) == 0x08 {
            break;
        }
        if n == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    assert!(
        !buf.is_empty() && (buf[0] & 0x0f) == 0x08,
        "expected first frame from server to be Close (opcode 0x8); got: {buf:?}"
    );
    let payload_len = (buf[1] & 0x7f) as usize;
    assert!(
        payload_len >= 2,
        "Close frame must carry a 2-byte code; got payload_len={payload_len}"
    );
    let code = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(
        code, 1002,
        "expected Close code 1002 on protocol-error path (FIX.md §3.1.4); got {code}"
    );
}

fn sec_websocket_accept(key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(MAGIC.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}
