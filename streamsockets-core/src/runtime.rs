//! Per-core current-thread runtimes pinned via `core_affinity`.
//!
//! MIGRATION.md §4 / §7.1 / §7.2: "N runtimes, one per core, each pinned, each
//! binding 0.0.0.0:BIND_PORT with SO_REUSEPORT". Each worker is a single OS
//! thread running a `tokio::runtime::Builder::new_current_thread()` runtime.
//! Per-tunnel state pins to one worker, so the WS task and UDP task share a
//! thread; cross-task communication uses local mpsc with no `Send` constraint.

use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::runtime::Builder;
use tracing::{debug, warn};

/// Resolve a worker-count knob from the environment with the documented defaults
/// from §10.1 / §10.2. The caller passes the env var name and a fallback.
///
/// Behavior: env unset or empty → `default_value()`; env set to "0" → 1 (single
/// worker), env set to a positive integer → that integer; env set to a
/// non-integer → panic at startup (matches Java behavior in `Utils.envValue`).
#[must_use]
pub fn resolve_worker_count(env_key: &str, default_value: impl FnOnce() -> usize) -> usize {
    match std::env::var(env_key) {
        Ok(v) if !v.is_empty() => match v.parse::<usize>() {
            Ok(0) => 1,
            Ok(n) => n,
            Err(_) => panic!("env var {env_key}={v} is not a valid worker count"),
        },
        _ => default_value().max(1),
    }
}

/// Default for client THREADS per §10.2: `n_cores * 2` on Linux, else `1`.
#[must_use]
pub fn client_threads_default() -> usize {
    if cfg!(target_os = "linux") {
        crate::num_cores().saturating_mul(2).max(1)
    } else {
        1
    }
}

/// Default for server PARENT_THREADS / CHILD_THREADS per §10.1: `n_cores`.
#[must_use]
pub fn server_threads_default() -> usize {
    crate::num_cores()
}

/// A handle to one pinned worker thread running its own current-thread runtime.
pub struct WorkerHandle {
    join: Option<JoinHandle<()>>,
    /// 0-based worker index — useful for the per-worker label in tracing/metrics.
    pub index: usize,
}

impl WorkerHandle {
    /// Wait for this worker thread to finish. After [`shutdown`] all workers
    /// should join in a finite amount of time.
    pub fn join(mut self) -> std::thread::Result<()> {
        if let Some(j) = self.join.take() {
            j.join()
        } else {
            Ok(())
        }
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        // We deliberately don't join in Drop — joining a runtime thread that's
        // still inside `block_on` would deadlock the caller. The supervisor
        // calls `WorkerHandle::join` explicitly after broadcasting a shutdown
        // signal.
        if let Some(_j) = self.join.take() {
            // detached
        }
    }
}

/// Spawn `count` OS threads, each running a current-thread tokio runtime
/// pinned to one core. The closure `make_task` is called on each runtime with
/// the worker index `i`; it must return the future the worker will `block_on`.
///
/// Returns one [`WorkerHandle`] per worker.
///
/// Panics propagate out of the worker thread; the supervisor catches them via
/// `WorkerHandle::join` returning `Err`.
pub fn spawn_per_core<F, Fut>(count: usize, make_task: F) -> Vec<WorkerHandle>
where
    F: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    let make_task = Arc::new(make_task);
    let mut handles = Vec::with_capacity(count);

    for i in 0..count {
        let core_id = cores.get(i % cores.len().max(1)).copied();
        let make_task = make_task.clone();
        let join = std::thread::Builder::new()
            .name(format!("ss-worker-{i}"))
            .spawn(move || {
                if let Some(c) = core_id {
                    if !core_affinity::set_for_current(c) {
                        warn!(worker = i, core = ?c, "failed to pin worker to core");
                    } else {
                        debug!(worker = i, core = ?c, "worker pinned to core");
                    }
                }
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .thread_name(format!("ss-worker-{i}"))
                    .build()
                    .expect("build current-thread runtime");
                rt.block_on(make_task(i));
            })
            .expect("spawn worker thread");
        handles.push(WorkerHandle {
            join: Some(join),
            index: i,
        });
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_worker_count_defaults() {
        std::env::remove_var("__SS_TEST_WORKERS__");
        let v = resolve_worker_count("__SS_TEST_WORKERS__", || 4);
        assert_eq!(v, 4);
    }

    #[test]
    fn resolve_worker_count_zero_clamps_to_one() {
        std::env::set_var("__SS_TEST_WORKERS_ZERO__", "0");
        let v = resolve_worker_count("__SS_TEST_WORKERS_ZERO__", || 4);
        assert_eq!(v, 1);
        std::env::remove_var("__SS_TEST_WORKERS_ZERO__");
    }

    #[test]
    fn resolve_worker_count_explicit() {
        std::env::set_var("__SS_TEST_WORKERS_8__", "8");
        let v = resolve_worker_count("__SS_TEST_WORKERS_8__", || 4);
        assert_eq!(v, 8);
        std::env::remove_var("__SS_TEST_WORKERS_8__");
    }

    #[test]
    #[should_panic(expected = "is not a valid worker count")]
    fn resolve_worker_count_invalid_panics() {
        std::env::set_var("__SS_TEST_WORKERS_BAD__", "potato");
        let _ = resolve_worker_count("__SS_TEST_WORKERS_BAD__", || 1);
    }

    #[test]
    fn server_default_at_least_one() {
        assert!(server_threads_default() >= 1);
    }

    #[test]
    fn client_default_at_least_one() {
        assert!(client_threads_default() >= 1);
    }

    #[test]
    fn spawn_per_core_runs_each_worker() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();
        let handles = spawn_per_core(3, move |i| {
            let counter = c2.clone();
            async move {
                counter.fetch_add(i + 1, Ordering::Relaxed);
            }
        });
        for h in handles {
            h.join().unwrap();
        }
        // 1 + 2 + 3
        assert_eq!(counter.load(Ordering::Relaxed), 6);
    }
}
