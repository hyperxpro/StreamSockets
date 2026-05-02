//! `StreamSockets` client entry point.
//!
//! Per MIGRATION.md §4 / §7.2: N current-thread runtimes, one per core, each
//! pinned and each binding the UDP listener with `SO_REUSEPORT` before any
//! `recv_from()` runs. Worker-0 also installs the SIGTERM/SIGINT handler;
//! the shared `CancellationToken` broadcasts shutdown to every worker.

#![allow(clippy::doc_markdown)]
//!
//! `EXIT_ON_FAILURE=true` causes the FSM (in any worker) to set a shared
//! `process_exit_code` to 1 and trigger graceful shutdown across every
//! worker; `main` then exits 1 after every worker thread has joined. (#2)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use streamsockets_client::fsm::{SharedExitCode, SharedLockedSource};
use streamsockets_client::{
    build_listener_udp_std, fsm, init_shared, spawn_signal_handler, ClientConfig,
};
use streamsockets_core::{
    client_threads_default, init_tracing, install_panic_hook, resolve_worker_count,
    sd_notify_stopping, spawn_per_core,
};
use tokio_util::sync::CancellationToken;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    init_tracing();
    install_panic_hook();

    let cfg = Arc::new(ClientConfig::from_env());
    if let Err(e) = cfg.validate() {
        eprintln!("configuration error: {e}");
        std::process::exit(2);
    }
    init_shared(&cfg);

    let n = resolve_worker_count("THREADS", client_threads_default).max(1);
    tracing::info!(workers = n, "spawning per-core client workers");

    let bind: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.bind_port).parse()?;
    let mut sockets: Vec<Option<std::net::UdpSocket>> = Vec::with_capacity(n);
    for i in 0..n {
        let s = build_listener_udp_std(bind)
            .map_err(|e| anyhow::anyhow!("worker {i} bind {bind} failed: {e}"))?;
        sockets.push(Some(s));
    }
    tracing::info!(%bind, workers = n, "all UDP listeners pre-bound (SO_REUSEPORT)");

    let shutdown = CancellationToken::new();
    let sockets = Arc::new(Mutex::new(sockets));

    // (#5) Process-wide lock-on cell shared by every worker's listener.
    let locked_source: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    // (#2) Shared exit code; FSM stamps 1 on terminal-with-EXIT_ON_FAILURE
    // and triggers shutdown; main reads after all workers join.
    let exit_code: SharedExitCode = Arc::new(AtomicI32::new(0));

    let cfg_for_workers = cfg.clone();
    let shutdown_for_workers = shutdown.clone();
    let sockets_for_workers = sockets.clone();
    let locked_for_workers = locked_source.clone();
    let exit_code_for_workers = exit_code.clone();

    let handles = spawn_per_core(n, move |idx| {
        let cfg = cfg_for_workers.clone();
        let shutdown = shutdown_for_workers.clone();
        let socket = sockets_for_workers.lock().expect("sockets mutex")[idx]
            .take()
            .expect("pre-bound UDP socket missing");
        let locked = locked_for_workers.clone();
        let exit_code = exit_code_for_workers.clone();
        async move {
            if let Err(e) = socket.set_nonblocking(true) {
                tracing::error!(worker = idx, "udp set_nonblocking failed: {e}");
                return;
            }
            let socket = match tokio::net::UdpSocket::from_std(socket) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(worker = idx, "udp from_std failed: {e}");
                    return;
                }
            };

            if idx == 0 {
                spawn_signal_handler(shutdown.clone());
            }

            if let Err(e) =
                fsm::run_fsm_with_socket(cfg, shutdown, socket, idx, locked, exit_code).await
            {
                tracing::error!(worker = idx, "fsm error: {e}");
            }
        }
    })
    .map_err(|e| anyhow::anyhow!("spawn_per_core: {e}"))?;

    // (#6) A worker-thread panic must not silently exit 0.
    let mut any_panicked = false;
    for h in handles {
        if let Err(e) = h.join() {
            tracing::error!("worker thread panicked: {e:?}");
            any_panicked = true;
        }
    }

    sd_notify_stopping();

    let code = exit_code.load(Ordering::SeqCst);
    if any_panicked && code == 0 {
        std::process::exit(1);
    }
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
