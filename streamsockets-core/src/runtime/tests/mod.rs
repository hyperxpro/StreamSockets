use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

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
    let counter = Arc::new(AtomicUsize::new(0));
    let c2 = counter.clone();
    let handles = spawn_per_core(3, move |i| {
        let counter = c2.clone();
        async move {
            counter.fetch_add(i + 1, Ordering::Relaxed);
        }
    })
    .expect("spawn_per_core");
    for h in handles {
        h.join().expect("test");
    }
    // 1 + 2 + 3
    assert_eq!(counter.load(Ordering::Relaxed), 6);
}
