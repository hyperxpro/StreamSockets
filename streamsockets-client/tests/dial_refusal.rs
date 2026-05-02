//! Defense-in-depth (#1): even when config validation has been bypassed,
//! the dial path must refuse to send AUTH_TOKEN over ws://.

use std::path::PathBuf;

use streamsockets_client::ws::{self, DialError};
use streamsockets_client::{ClientConfig, RedactedString};

fn cfg_ws_with_token() -> ClientConfig {
    ClientConfig {
        bind_address: "127.0.0.1".into(),
        bind_port: 9000,
        // ws:// (plaintext) + non-empty token. Even if the operator wrote
        // ClientConfig literally and skipped validate(), the dial path
        // refuses before opening a TCP connection.
        websocket_uri: "ws://127.0.0.1:1/tunnel".into(),
        auth_token: RedactedString::new("super-secret".into()),
        route: "127.0.0.1:8888".into(),
        ping_interval_ms: 5000,
        ping_timeout_ms: 10_000,
        ping_permitted_misses: 1,
        retry_initial_delay_ms: 1000,
        retry_max_delay_ms: 30_000,
        retry_budget: 100,
        udp_timeout_secs: 300,
        exit_on_failure: false,
        queue_max_bytes: 1_048_576,
        queue_drain_timeout_ms: 30_000,
        threads: 1,
        max_frame_size: 65535,
        udp_channel_capacity: 1024,
        allow_insecure_auth: false,
        allow_no_auth: false,
        tls_ca_file: Option::<PathBuf>::None,
    }
}

#[tokio::test]
async fn ws_plus_token_refused_at_dial_time() {
    let cfg = cfg_ws_with_token();
    let res = ws::dial(&cfg).await;
    match res {
        Err(DialError::InsecureScheme) => {}
        Err(other) => panic!("expected DialError::InsecureScheme, got Err({other})"),
        Ok(_) => panic!("expected DialError::InsecureScheme, got Ok(WebSocket)"),
    }
}

#[tokio::test]
async fn ws_plus_token_with_opt_in_proceeds_to_tcp() {
    // With ALLOW_INSECURE_AUTH=true the dial path proceeds; we expect a TCP
    // failure (connection refused / unreachable) rather than InsecureScheme.
    let mut cfg = cfg_ws_with_token();
    cfg.allow_insecure_auth = true;
    let res = ws::dial(&cfg).await;
    match res {
        Err(DialError::Tcp(_)) => {}
        Err(DialError::InsecureScheme) => panic!("opt-in should bypass refusal"),
        Err(other) => {
            eprintln!("dial returned Err({other}); not InsecureScheme — OK for this test");
        }
        Ok(_) => {
            eprintln!("dial returned Ok(WebSocket); not InsecureScheme — OK for this test");
        }
    }
}

#[tokio::test]
async fn empty_token_over_ws_allowed_no_token_to_leak() {
    // Empty token over ws:// is not a token-leak risk; the dial path
    // should not raise InsecureScheme. (Config validation handles the
    // missing-token policy separately.)
    let mut cfg = cfg_ws_with_token();
    cfg.auth_token = RedactedString::new(String::new());
    let res = ws::dial(&cfg).await;
    match res {
        Err(DialError::InsecureScheme) => panic!("empty token must not trigger InsecureScheme"),
        _ => {}
    }
}
