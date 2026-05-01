//! 1000-tunnel × 10 pps × configurable duration FD-leak soak test.
//!
//! Spec §11.3: "Soak: 1000 tunnels × 10 pps × 24h; assert no FD leak, no
//! memory growth, no metric drift." This test is `#[ignore]`'d and only runs
//! when the operator opts in:
//!
//! ```bash
//! # Run manually: cargo test --test soak_fd_leak -- --ignored --nocapture SOAK_DURATION_HOURS=24
//! SOAK_DURATION_HOURS=24 cargo test --release --test soak_fd_leak -- --ignored --nocapture
//! ```
//!
//! For release-tag CI we run the same code with `SOAK_DURATION_HOURS=0.083`
//! (5 minutes) — the tunnel-create / tunnel-destroy path is the same and a
//! 5-minute window catches a leak that doubles every minute (the most common
//! shape).
//!
//! Sampling: every 60 s we read `/proc/self/fd` and assert no monotonic
//! growth beyond a small variance window. The first 60 s is treated as
//! warmup (TCP TIME_WAIT churn settles) and excluded from the assertion.

#![cfg(target_os = "linux")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;

/// Default tunnel count. The 24h soak runs at 1000; the 5-minute CI variant
/// runs at the same count to surface scaling-related leaks (per-tunnel
/// state, per-tunnel metrics labels, etc).
const TUNNEL_COUNT: usize = 1000;
/// 10 pps per tunnel == 10_000 datagrams/s through the workspace (small
/// enough to run on CI hardware, large enough to keep every tunnel
/// active so its idle-timeout never fires).
const PPS_PER_TUNNEL: u64 = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn soak_fd_leak_one_thousand_tunnels() {
    common::init_tracing_for_tests();

    let duration = parse_soak_duration();
    eprintln!(
        "soak_fd_leak: tunnels={TUNNEL_COUNT}, pps_per_tunnel={PPS_PER_TUNNEL}, \
         duration={:?}",
        duration
    );

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;

    let yaml = format!(
        r#"
accounts:
  - name: shared
    token: 'shared-token'
    reuse: true
    routes:
      - '127.0.0.1:{echo_port}'
    allowedIps:
      - '127.0.0.1'
"#
    );
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(500)).await;

    // Spin up TUNNEL_COUNT clients. Each client gets its own UDP listener
    // port; the kernel handles SO_REUSEPORT placement.
    let mut udp_ports = Vec::with_capacity(TUNNEL_COUNT);
    let mut clients = Vec::with_capacity(TUNNEL_COUNT);
    for _ in 0..TUNNEL_COUNT {
        let p = common::free_udp_port().await;
        udp_ports.push(p);
        let mut cfg = common::default_client_cfg(server_port, p, echo_port);
        cfg.auth_token = "shared-token".into();
        cfg.retry_initial_delay_ms = 100;
        cfg.retry_max_delay_ms = 1000;
        clients.push(common::spawn_client(cfg).await);
    }
    eprintln!(
        "soak_fd_leak: {} clients spawned; settling 5s before priming",
        TUNNEL_COUNT
    );
    common::settle(Duration::from_secs(5)).await;

    // Prime tunnels and start a steady traffic generator per tunnel.
    let games: Vec<Arc<UdpSocket>> = {
        let mut v = Vec::with_capacity(TUNNEL_COUNT);
        for &p in &udp_ports {
            let g = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target: std::net::SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
            g.send_to(b"prime", target).await.unwrap();
            v.push(Arc::new(g));
        }
        v
    };
    common::settle(Duration::from_secs(2)).await;

    // Steady traffic: 10 pps per tunnel.
    let stop = Arc::new(Mutex::new(false));
    let mut traffic_tasks = Vec::with_capacity(TUNNEL_COUNT);
    for (g, &p) in games.iter().zip(udp_ports.iter()) {
        let g = g.clone();
        let stop = stop.clone();
        let target: std::net::SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
        let interval = Duration::from_millis(1000 / PPS_PER_TUNNEL);
        traffic_tasks.push(tokio::spawn(async move {
            let payload = vec![0u8; 64];
            loop {
                if *stop.lock() {
                    return;
                }
                let _ = g.send_to(&payload, target).await;
                tokio::time::sleep(interval).await;
            }
        }));
    }

    // Sample /proc/self/fd every 60 s.
    let start = Instant::now();
    let warmup = Duration::from_secs(60);
    let mut samples: Vec<(Duration, usize)> = Vec::new();
    let mut baseline: Option<usize> = None;

    while start.elapsed() < duration {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let count = count_fds();
        let elapsed = start.elapsed();
        eprintln!("soak_fd_leak: t={:>6}s fd_count={count}", elapsed.as_secs());
        samples.push((elapsed, count));
        if elapsed >= warmup && baseline.is_none() {
            baseline = Some(count);
            eprintln!("soak_fd_leak: baseline FD count after warmup = {count}");
        }
    }

    // Stop traffic.
    *stop.lock() = true;
    for t in traffic_tasks {
        let _ = t.await;
    }

    // Assert: no growth beyond a small tolerance over baseline. We allow
    // 2 × TUNNEL_COUNT (=2000) headroom for transient TCP TIME_WAIT and
    // ephemeral UDP sockets churning.
    let baseline = baseline.expect("ran < warmup; increase SOAK_DURATION_HOURS");
    let tolerance = (TUNNEL_COUNT as i64) * 2;
    let mut max_observed = baseline;
    for (t, c) in &samples {
        if *t < warmup {
            continue;
        }
        max_observed = max_observed.max(*c);
        let drift = *c as i64 - baseline as i64;
        assert!(
            drift <= tolerance,
            "FD leak detected: at t={:?} fd_count={c}, baseline={baseline}, drift={drift}, \
             tolerance={tolerance}",
            t
        );
    }
    eprintln!(
        "soak_fd_leak: PASS — baseline={baseline}, max_observed={max_observed}, \
         drift={}, tolerance={tolerance}",
        max_observed as i64 - baseline as i64
    );
}

/// Read `SOAK_DURATION_HOURS`. Defaults to 24h. Accepts fractional values
/// (e.g. `0.083` = 5 minutes) for the release-tag CI variant.
fn parse_soak_duration() -> Duration {
    match std::env::var("SOAK_DURATION_HOURS") {
        Ok(s) => {
            let hours: f64 = s
                .parse()
                .unwrap_or_else(|_| panic!("SOAK_DURATION_HOURS={s} is not a valid number"));
            Duration::from_secs_f64(hours * 3600.0)
        }
        Err(_) => Duration::from_secs(24 * 3600),
    }
}

fn count_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}
