//! Spec §11.1 (ExitOnFailureTest): a client configured with `EXIT_ON_FAILURE=true`
//! and a server that returns 401 must call `std::process::exit(1)`. Verified by
//! spawning the client binary as a subprocess and asserting the exit code.
//!
//! This is the only test that requires the binary to exist — `cargo test --release`
//! builds it, and `assert_cmd::Command::cargo_bin` finds it via cargo metadata.

use std::time::Duration;

use std::process::{Command, Stdio};

mod common;

/// Locate the built `streamsockets-client` binary. `CARGO_BIN_EXE_*` env vars
/// are only set in the same crate as the binary; for tests in a separate
/// crate we walk from `CARGO_MANIFEST_DIR` up to the workspace root and join
/// `target/<profile>/streamsockets-client`.
fn locate_client_binary() -> std::path::PathBuf {
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

#[tokio::test]
async fn client_exits_1_on_terminal_status() {
    common::init_tracing_for_tests();

    let bin = locate_client_binary();
    if !bin.exists() {
        // Build it once with the same profile cargo test is using.
        let profile = if cfg!(debug_assertions) {
            "dev"
        } else {
            "release"
        };
        let status = std::process::Command::new(env!("CARGO"))
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
    assert!(
        bin.exists(),
        "streamsockets-client binary not found at {}",
        bin.display()
    );

    // Spawn server with an accounts.yaml that grants no token, then attempt to
    // dial with an unknown token + EXIT_ON_FAILURE=true. Server returns 401,
    // client classifies as terminal, calls exit(1).
    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;
    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);
    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;
    common::settle(Duration::from_millis(200)).await;

    let client_udp = common::free_udp_port().await;
    let bin_path = bin.clone();

    // Block in a spawn_blocking so the parent runtime keeps running while the
    // child binary executes.
    let exit_code = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&bin_path);
        cmd.env("BIND_ADDRESS", "127.0.0.1")
            .env("BIND_PORT", client_udp.to_string())
            .env(
                "WEBSOCKET_URI",
                format!("ws://127.0.0.1:{server_port}/tunnel"),
            )
            .env("AUTH_TOKEN", "wrong-token")
            .env("ROUTE", format!("127.0.0.1:{echo_port}"))
            .env("EXIT_ON_FAILURE", "true")
            .env("RETRY_INITIAL_DELAY_SECONDS", "1")
            .env("RETRY_MAX_DELAY_SECONDS", "1")
            // Tight budget so the test terminates via the RETRY_BUDGET path
            // even if the 401 isn't recognized as `is_terminal()` by the
            // hyper/fastwebsockets handshake error mapping. Either way exits 1.
            .env("RETRY_BUDGET", "3")
            .env("LOG_LEVEL", "warn")
            // Disable systemd integration so we don't pollute the test env.
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn client");

        // The client's FSM idles waiting for a UDP packet (§6.1). Send several
        // from a sibling thread (with retry-style retries) so even if the
        // listener isn't bound by the first packet's send time, subsequent
        // packets reach it. FSM transitions Connecting → fails 401 (or exhausts
        // RETRY_BUDGET=3) → terminate(EXIT_ON_FAILURE=true) → exit(1).
        let target = format!("127.0.0.1:{client_udp}");
        std::thread::spawn(move || {
            for delay_ms in [500u64, 800, 1100, 1500, 2000, 3000] {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                if let Ok(g) = std::net::UdpSocket::bind("127.0.0.1:0") {
                    let _ = g.send_to(b"trigger", &target);
                }
            }
        });

        // Bound: terminal via RETRY_BUDGET=3 with 1s delays = ~5s + dial latency.
        // 30s gives ample headroom even on slow CI runners.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().ok().flatten() {
                return status.code().unwrap_or(-1);
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                return -1;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })
    .await
    .unwrap();

    assert_eq!(exit_code, 1, "expected exit code 1 on terminal 401");
}
