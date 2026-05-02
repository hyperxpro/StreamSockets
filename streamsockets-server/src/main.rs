//! `StreamSockets` server entry point.
//!
//! Per MIGRATION.md §4 / §7.1: N current-thread runtimes, one per core, each
//! pinned and each binding the listen port with `SO_REUSEPORT` before any
//! `accept()` runs. Worker-0 also hosts the metrics service, the SIGTERM
//! handler, the auth-reload watcher, and the systemd watchdog heartbeat.

#![allow(clippy::doc_markdown)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use streamsockets_core::{
    init_tracing, install_panic_hook, resolve_worker_count, sd_notify_ready, sd_notify_stopping,
    server_threads_default, spawn_per_core,
};
use streamsockets_server::{
    build_metrics_listener_std, build_tunnel_listener_std, init_shared, run_worker, ServerConfig,
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    init_tracing();
    install_panic_hook();

    // TOKIO_CONSOLE_BIND (MIGRATION.md §10.1): if set, the operator wants the
    // tokio-console subscriber bound for live task introspection. The current
    // build does not link `console-subscriber` (heavy dep, deferred to v2.1).
    // Surface a warn so the misconfiguration is visible at startup rather
    // than silent.
    if let Some(bind) = std::env::var_os("TOKIO_CONSOLE_BIND") {
        tracing::warn!(
            value = %bind.to_string_lossy(),
            "TOKIO_CONSOLE_BIND is set but this build does not include console-subscriber; \
             ignoring. Rebuild with --features tokio-console once the v2.1 console-subscriber \
             integration ships."
        );
    }

    let cfg = Arc::new(ServerConfig::from_env());

    // PARENT_THREADS controls the number of accept-loop workers. CHILD_THREADS
    // is read for forwards-compatibility with the Java-era split: Java used a
    // parent EventLoopGroup for accept and a child group for I/O; in the Rust
    // per-core model both run on the same per-worker current-thread runtime,
    // so we honor whichever knob is larger (matches the §10.1 documented
    // semantics — "now equals worker runtimes (same value)").
    let parent = resolve_worker_count("PARENT_THREADS", server_threads_default);
    let child = resolve_worker_count("CHILD_THREADS", server_threads_default);
    let n = parent.max(child).max(1);
    tracing::info!(workers = n, "spawning per-core server workers");

    let bind: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.bind_port).parse()?;
    let backlog = cfg.listen_backlog;
    let mut tunnel_listeners: Vec<Option<std::net::TcpListener>> = Vec::with_capacity(n);
    for i in 0..n {
        let l = build_tunnel_listener_std(bind, backlog)
            .map_err(|e| anyhow::anyhow!("worker {i} bind {bind} failed: {e}"))?;
        tunnel_listeners.push(Some(l));
    }
    tracing::info!(%bind, workers = n, backlog, "all tunnel listeners pre-bound (SO_REUSEPORT)");

    let metrics_listener: Option<std::net::TcpListener> = if cfg.metrics_enabled {
        let metrics_addr: SocketAddr =
            format!("{}:{}", cfg.metrics_bind_address, cfg.metrics_port).parse()?;
        let l = build_metrics_listener_std(metrics_addr, backlog)?;
        tracing::info!(%metrics_addr, "metrics listener pre-bound");
        Some(l)
    } else {
        None
    };

    let server = init_shared(cfg)?;

    // All required listeners are bound — flip /readyz and notify systemd.
    // Per MIGRATION.md §9.3 / §12.2: READY=1 fires after first successful
    // bind. With pre-binding, that's right here, before any worker accepts.
    sd_notify_ready();
    server.health.mark_ready();

    let listeners = Arc::new(Mutex::new(tunnel_listeners));
    let metrics_listener = Arc::new(Mutex::new(metrics_listener));

    let server_for_workers = server.clone();
    let listeners_for_workers = listeners.clone();
    let metrics_for_workers = metrics_listener.clone();

    let handles = spawn_per_core(n, move |idx| {
        let server = server_for_workers.clone();
        let listener = listeners_for_workers.lock().expect("listeners mutex")[idx]
            .take()
            .expect("pre-bound tunnel listener missing");
        let metrics = if idx == 0 {
            metrics_for_workers.lock().expect("metrics mutex").take()
        } else {
            None
        };
        async move {
            run_worker(server, listener, idx, metrics).await;
        }
    })
    .map_err(|e| anyhow::anyhow!("spawn_per_core: {e}"))?;

    // Block until every worker exits cleanly. spawn_per_core's worker threads
    // detach by default; we explicitly join here to honor the contract that
    // SIGTERM → graceful drain → process exit only after every worker has
    // finished its accept loop.
    for h in handles {
        if let Err(e) = h.join() {
            tracing::error!("worker thread panicked: {e:?}");
        }
    }

    sd_notify_stopping();
    tracing::info!("graceful shutdown complete");
    Ok(())
}
