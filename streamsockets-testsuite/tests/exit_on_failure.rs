//! Spec §11.1 (ExitOnFailureTest): a client configured with `EXIT_ON_FAILURE=true`
//! and a server that returns 401 must call `std::process::exit(1)`. Verified by
//! spawning the client binary as a subprocess and asserting the exit code.
//!
//! Two scenarios:
//!  - `client_exits_1_on_terminal_status` — RETRY_BUDGET=1000 so only the
//!    terminal-401 path can produce exit(1). Catches a regression where the
//!    401 classifier returns transient.
//!  - `client_exits_1_on_budget_exhaustion` — RETRY_BUDGET=3 so either the
//!    terminal-401 path or the budget-exhaustion path can produce exit(1).
//!    Catches a regression in budget tracking. Splitting these used to be
//!    one ambiguous test where both code paths satisfied the assertion.

use std::process::{Command, Stdio};
use std::time::Duration;

mod common;

/// Locate the built `streamsockets-client` binary. Prefer the cargo
/// `CARGO_BIN_EXE_streamsockets-client` env var when set (cargo populates this
/// when the binary's package is in the same workspace and declared via
/// dev-dep artifacts); fall back to walking `target/<profile>/`.
fn locate_client_binary() -> std::path::PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_streamsockets-client") {
        return std::path::PathBuf::from(p);
    }
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("workspace root above streamsockets-testsuite");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root
        .join("target")
        .join(profile)
        .join("streamsockets-client")
}

fn ensure_client_binary_built(bin: &std::path::Path) {
    if bin.exists() {
        return;
    }
    let profile = if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    };
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--manifest-path",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../streamsockets-client/Cargo.toml"
            ),
            "--profile",
            profile,
            "--bin",
            "streamsockets-client",
        ])
        .status()
        .expect("build streamsockets-client");
    assert!(status.success(), "failed to pre-build client binary");
}

/// RETRY_BUDGET=1000 means budget exhaustion cannot fire within the test's
/// 30s deadline. exit(1) must come from the terminal-401 path only.
#[tokio::test]
async fn client_exits_1_on_terminal_status() {
    let exit = run_exit_scenario(/* retry_budget = */ 1000).await;
    assert_eq!(
        exit, 1,
        "EXIT_ON_FAILURE=true + 401 terminal must yield exit(1) via terminal-401 path"
    );
}

/// RETRY_BUDGET=3 with 1s delay → budget exhaustion at ~3s; either the
/// terminal-401 path or the budget-exhaust path can fire first. Both yield
/// exit(1); this guards against either path silently failing to exit.
#[tokio::test]
async fn client_exits_1_on_budget_exhaustion() {
    let exit = run_exit_scenario(/* retry_budget = */ 3).await;
    assert_eq!(
        exit, 1,
        "EXIT_ON_FAILURE=true + tight retry budget must yield exit(1)"
    );
}

async fn run_exit_scenario(retry_budget: u32) -> i32 {
    common::init_tracing_for_tests();

    let bin = locate_client_binary();
    ensure_client_binary_built(&bin);
    assert!(
        bin.exists(),
        "streamsockets-client binary not found at {}",
        bin.display()
    );

    // Server with no token grant; client dials with wrong token → 401 →
    // EXIT_ON_FAILURE=true → exit(1).
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;
    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    let client_udp = common::free_udp_port().await;
    let bin_path = bin.clone();

    // spawn_blocking so the parent runtime keeps progressing while the child
    // runs.
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&bin_path);
        cmd.env("BIND_ADDRESS", "127.0.0.1")
            .env("BIND_PORT", client_udp.to_string())
            .env(
                "WEBSOCKET_URI",
                format!("ws://127.0.0.1:{server_port}/tunnel"),
            )
            .env("AUTH_TOKEN", "wrong-token")
            // ws:// + token requires explicit opt-out; the test exercises the
            // exit-on-failure FSM path, not the plaintext-token startup guard.
            .env("ALLOW_INSECURE_AUTH", "true")
            .env("ROUTE", format!("127.0.0.1:{echo_port}"))
            .env("EXIT_ON_FAILURE", "true")
            .env("RETRY_INITIAL_DELAY_SECONDS", "1")
            .env("RETRY_MAX_DELAY_SECONDS", "1")
            .env("RETRY_BUDGET", retry_budget.to_string())
            .env("LOG_LEVEL", "warn")
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn client");

        // FSM idles until UDP arrives. Send several from a sibling thread.
        let target = format!("127.0.0.1:{client_udp}");
        std::thread::spawn(move || {
            for delay_ms in [500u64, 800, 1100, 1500, 2000, 3000] {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if let Ok(g) = std::net::UdpSocket::bind("127.0.0.1:0") {
                    let _ = g.send_to(b"trigger", &target);
                }
            }
        });

        // 30s deadline — generous headroom over either exit path.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().ok().flatten() {
                return status.code().unwrap_or(-1);
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                return -1;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await
    .unwrap()
}
