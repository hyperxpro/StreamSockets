//! `StreamSockets` client entry point.
//!
//! Per MIGRATION.md §4 / §7.2: N current-thread runtimes, one per core, each
//! pinned and each binding the UDP listener with `SO_REUSEPORT` before any
//! `recv_from()` runs. Worker-0 also installs the SIGTERM/SIGINT handler;
//! the shared `CancellationToken` broadcasts shutdown to every worker.

#![allow(clippy::doc_markdown)]
//!
//! `EXIT_ON_FAILURE=true` causes the FSM (in any worker) to call
//! `std::process::exit(1)` from a `Terminated` transition — this terminates
//! every worker process-wide, which is the desired k8s/systemd
//! restart-on-failure semantics.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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
    init_shared(&cfg);

    let n = resolve_worker_count("THREADS", client_threads_default).max(1);
    tracing::info!(workers = n, "spawning per-core client workers");

    // Pre-bind N UDP sockets with SO_REUSEPORT BEFORE any worker enters its
    // tokio runtime. The kernel UDP fanout hash sees the full group from the
    // first datagram.
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

    let cfg_for_workers = cfg.clone();
    let shutdown_for_workers = shutdown.clone();
    let sockets_for_workers = sockets.clone();

    let handles = spawn_per_core(n, move |idx| {
        let cfg = cfg_for_workers.clone();
        let shutdown = shutdown_for_workers.clone();
        let socket = sockets_for_workers.lock().expect("sockets mutex")[idx]
            .take()
            .expect("pre-bound UDP socket missing");
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
                // Worker-0 owns the SIGTERM handler. The shared
                // `shutdown` token broadcasts to every other worker via
                // their cloned token in this closure.
                spawn_signal_handler(shutdown.clone());
            }

            if let Err(e) = fsm::run_fsm_with_socket(cfg, shutdown, socket, idx).await {
                tracing::error!(worker = idx, "fsm error: {e}");
            }
        }
    });

    for h in handles {
        if let Err(e) = h.join() {
            tracing::error!("worker thread panicked: {e:?}");
        }
    }

    sd_notify_stopping();
    Ok(())
}
