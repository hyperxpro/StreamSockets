//! Integration tests for `ClientConfig::validate` (#1, #7, #8, #9, #10, #14, #17).

use std::path::PathBuf;

use streamsockets_client::{parse_route, ClientConfig, ConfigError, RedactedString};

fn base_cfg() -> ClientConfig {
    ClientConfig {
        bind_address: "127.0.0.1".into(),
        bind_port: 9000,
        websocket_uri: "wss://example.com/tunnel".into(),
        auth_token: RedactedString::new("token".into()),
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

#[test]
fn happy_path_validates() {
    base_cfg().validate().expect("base should validate");
}

#[test]
fn ws_with_token_refused() {
    // (#1) ws:// + AUTH_TOKEN must be refused without ALLOW_INSECURE_AUTH.
    let mut c = base_cfg();
    c.websocket_uri = "ws://example.com/tunnel".into();
    match c.validate() {
        Err(ConfigError::InsecureScheme) => {}
        other => panic!("expected InsecureScheme, got {other:?}"),
    }
}

#[test]
fn ws_with_token_opt_in_allowed() {
    let mut c = base_cfg();
    c.websocket_uri = "ws://example.com/tunnel".into();
    c.allow_insecure_auth = true;
    c.validate()
        .expect("ALLOW_INSECURE_AUTH=true should validate");
}

#[test]
fn empty_token_refused() {
    // (#8)
    let mut c = base_cfg();
    c.auth_token = RedactedString::new(String::new());
    match c.validate() {
        Err(ConfigError::MissingAuthToken) => {}
        other => panic!("expected MissingAuthToken, got {other:?}"),
    }
}

#[test]
fn empty_token_opt_in_allowed() {
    let mut c = base_cfg();
    c.auth_token = RedactedString::new(String::new());
    c.allow_no_auth = true;
    c.validate().expect("ALLOW_NO_AUTH=true should validate");
}

#[test]
fn threads_zero_rejected() {
    // (#9)
    let mut c = base_cfg();
    c.threads = 0;
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn threads_above_cap_rejected() {
    let mut c = base_cfg();
    c.threads = 257;
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn max_frame_size_below_floor_rejected() {
    // (#10)
    let mut c = base_cfg();
    c.max_frame_size = 1499;
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn max_frame_size_above_ceiling_rejected() {
    let mut c = base_cfg();
    // The ceiling is 65536 (the spec default); 65537 is the first rejected value.
    c.max_frame_size = 65_537;
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn route_unbracketed_ipv6_rejected() {
    // (#7) Unbracketed v6 literal must be refused; the old `rsplit_once(':')`
    // parser silently ate this case.
    let mut c = base_cfg();
    c.route = "::1:8888".into();
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn route_bracketed_ipv6_accepted() {
    let mut c = base_cfg();
    c.route = "[::1]:8888".into();
    c.validate().expect("bracketed v6 should validate");
}

#[test]
fn route_v4_accepted() {
    let mut c = base_cfg();
    c.route = "192.0.2.10:9999".into();
    c.validate().expect("v4 should validate");
}

#[test]
fn route_dns_name_accepted() {
    let mut c = base_cfg();
    c.route = "relay.example.com:443".into();
    c.validate().expect("DNS name should validate");
}

#[test]
fn route_port_zero_rejected() {
    // (#17) port==0 is invalid.
    let mut c = base_cfg();
    c.route = "127.0.0.1:0".into();
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn websocket_port_zero_rejected() {
    let mut c = base_cfg();
    c.websocket_uri = "wss://example.com:0/tunnel".into();
    assert!(matches!(c.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn parse_route_strict_rejects_ambiguous() {
    // (#7) Direct parse_route check.
    assert!(parse_route("::1:8888").is_none());
    assert!(parse_route(":8888").is_none());
    assert!(parse_route("[::1]:8888").is_some());
    assert!(parse_route("127.0.0.1:8888").is_some());
    assert!(parse_route("host.example:443").is_some());
}
