use super::*;

/// Touch every counter/gauge so it appears in TextEncoder output, then
/// assert ALL_METRIC_NAMES is fully covered.
#[test]
fn registry_renders_every_spec_metric() {
    let m = Metrics::new();

    // Preserved (§9.1)
    m.record_connection_start("alice");
    m.record_bytes_received("alice", 100);
    m.record_bytes_sent("alice", 200);
    m.record_connection_end("alice", 1.0);

    // New (§9.2)
    m.handshake_failures.with_label_values(&["auth"]).inc();
    m.handshake_version.with_label_values(&["v2"]).set(1.0);
    m.handshake_timeouts.inc();
    m.tls_handshake_failures
        .with_label_values(&["bad_cert"])
        .inc();
    m.reconnect_attempts.with_label_values(&["alice"]).inc();
    m.reconnect_state.with_label_values(&["alice"]).set(0.0);
    m.ping_timeouts.with_label_values(&["alice"]).inc();
    m.ping_rtt_seconds
        .with_label_values(&["alice"])
        .observe(0.012);
    m.ws_close.with_label_values(&["server", "1000"]).inc();
    m.protocol_violations
        .with_label_values(&["text_frame"])
        .inc();
    m.upstream_dns_failures.inc();
    m.upstream_connect_failures.inc();
    m.upstream_unreachable.inc();
    m.upstream_send_drops.inc();
    m.downstream_queue_drops.inc();
    m.upstream_truncated.inc();
    m.queue_depth_bytes.with_label_values(&["alice"]).set(0.0);
    m.queue_dropped
        .with_label_values(&["alice", "overflow"])
        .inc();
    m.queue_purged.with_label_values(&["alice"]).inc();
    m.client_foreign_sources.inc();
    m.active_tunnels.set(0.0);
    m.udp_egress_socket_buffer_bytes
        .with_label_values(&["recv"])
        .set(4_194_304.0);
    m.runtime_kind.with_label_values(&["tokio"]).set(1.0);
    m.client_state.with_label_values(&["live"]).set(1.0);

    // §13.3 row 13
    m.udp_idle_closes.inc();

    let text = String::from_utf8(m.encode_text().expect("encode")).expect("test");
    for name in ALL_METRIC_NAMES {
        assert!(text.contains(name), "missing metric: {name}");
    }

    // Verify exact count is in lockstep with spec — guards against silent
    // additions to ALL_METRIC_NAMES.
    // 6 preserved from v1.7.0 + 24 new in v2 (incl. upstream_truncated_total and
    // downstream_queue_drops_total) + 1 (udp_idle_closes_total) = 31.
    assert_eq!(
        ALL_METRIC_NAMES.len(),
        31,
        "ALL_METRIC_NAMES count drifted from spec (6 preserved + 24 new + udp_idle_closes_total)"
    );
}

/// Every documented `handshake_failures_total{reason}` value renders.
#[test]
fn handshake_reasons_distinct_labels() {
    let m = Metrics::new();
    for r in [
        "auth",
        "ip_denied",
        "route_denied",
        "reuse_conflict",
        "capacity",
        "bad_request",
    ] {
        m.handshake_failures.with_label_values(&[r]).inc();
    }
    let text = String::from_utf8(m.encode_text().expect("encode")).expect("test");
    for r in [
        "auth",
        "ip_denied",
        "route_denied",
        "reuse_conflict",
        "capacity",
        "bad_request",
    ] {
        assert!(
            text.contains(&format!("reason=\"{r}\"")),
            "missing reason label `{r}` in encoded text"
        );
    }
}

/// `ws_close_total{side}` accepts both `client` and `server` (per §13.3
/// rows 11/12 — the SHIP-BLOCKER from VERDICT.md was that the server
/// always emitted `server` for received closes; the metric itself supports
/// both).
#[test]
fn ws_close_accepts_both_sides() {
    let m = Metrics::new();
    m.ws_close.with_label_values(&["server", "1000"]).inc();
    m.ws_close.with_label_values(&["client", "1000"]).inc();
    let text = String::from_utf8(m.encode_text().expect("encode")).expect("test");
    assert!(text.contains("side=\"server\""));
    assert!(text.contains("side=\"client\""));
}

/// Histograms expose the spec'd buckets.
#[test]
fn connection_duration_buckets_match_spec() {
    let m = Metrics::new();
    m.record_connection_start("a");
    m.record_connection_end("a", 7.0);
    let text = String::from_utf8(m.encode_text().expect("encode")).expect("test");
    // Spec §9.1: buckets 1, 5, 10, 30, 60, 300, 600, 1800, 3600
    for b in ["1", "5", "10", "30", "60", "300", "600", "1800", "3600"] {
        let needle = format!("le=\"{b}\"");
        assert!(text.contains(&needle), "missing bucket le={b}");
    }
}

/// `runtime_kind` accepts the three spec'd labels: io_uring, epoll, tokio.
#[test]
fn runtime_kind_accepts_three_labels() {
    let m = Metrics::new();
    for k in ["io_uring", "epoll", "tokio"] {
        m.runtime_kind.with_label_values(&[k]).set(1.0);
    }
    let text = String::from_utf8(m.encode_text().expect("encode")).expect("test");
    for k in ["io_uring", "epoll", "tokio"] {
        assert!(text.contains(&format!("kind=\"{k}\"")), "missing kind={k}");
    }
}

/// /readyz must remain 503 until `mark_ready()` is called. Health state
/// behavior is the contract; the HTTP wiring is exercised in the server's
/// integration suite.
#[test]
fn health_state_initially_not_ready_or_draining() {
    let h = HealthState::new();
    assert!(!h.is_ready());
    assert!(!h.is_draining());
    h.mark_ready();
    assert!(h.is_ready());
    h.mark_draining();
    assert!(h.is_draining());
}
