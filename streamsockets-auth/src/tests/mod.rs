use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;
use tracing::{Event, Level};
use tracing_subscriber::{
    layer::Context,
    layer::SubscriberExt,
    registry::{LookupSpan, Registry},
    Layer,
};

struct InfoEventCounter {
    count: Arc<AtomicUsize>,
}

impl<S> Layer<S> for InfoEventCounter
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() == Level::INFO {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn sample_file() -> AccountsFile {
    AccountsFile {
        accounts: vec![
            Account {
                name: "user1".into(),
                token: "tok1".into(),
                reuse: false,
                routes: vec!["127.0.0.1:8888".into()],
                allowed_ips: vec!["127.0.0.1".into(), "192.168.1.0/24".into()],
            },
            Account {
                name: "user2".into(),
                token: "tok2".into(),
                reuse: true,
                routes: vec!["example.com:5050".into()],
                allowed_ips: vec!["10.0.0.0/8".into()],
            },
        ],
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test")
}

#[test]
fn build_and_query() {
    let snap = AccountsSnapshot::build(sample_file()).expect("test");
    let m = snap.authenticate("tok1", "127.0.0.1:8888", ip("127.0.0.1"));
    assert!(m.is_some());
    assert_eq!(m.expect("test").account.name, "user1");
    assert!(snap
        .authenticate("tok1", "127.0.0.1:8888", ip("192.168.1.50"))
        .is_some());
    assert!(snap
        .authenticate("tok1", "127.0.0.1:8888", ip("10.0.0.1"))
        .is_none());
    assert!(snap
        .authenticate("badtoken", "127.0.0.1:8888", ip("127.0.0.1"))
        .is_none());
    assert!(snap
        .authenticate("tok1", "wrong.route:1", ip("127.0.0.1"))
        .is_none());
}

#[test]
fn duplicate_token_rejected_reports_account_name_not_token() {
    let mut f = sample_file();
    f.accounts[1].token = "tok1".into();
    let r = AccountsSnapshot::build(f);
    match r {
        Err(AuthError::DuplicateToken(name)) => {
            assert_eq!(name, "user2");
            let displayed = format!("{}", AuthError::DuplicateToken(name));
            assert!(!displayed.contains("tok1"));
        }
        other => panic!("expected DuplicateToken, got {other:?}"),
    }
}

#[test]
fn lease_no_reuse_conflicts() {
    let auth = TokenAuthentication::from_accounts(sample_file()).expect("test");
    let snap = auth.snapshot_arc();
    let hash = token_hash(b"tok1");
    let acc = snap.by_token_hash.get(&hash).expect("test").account.clone();
    let g1 = auth.leases().try_lease_arc(&acc).expect("test");
    let r2 = auth.leases().try_lease_arc(&acc);
    assert!(matches!(r2, Err(LeaseError::Conflict)));
    drop(g1);
    let _g3 = auth.leases().try_lease_arc(&acc).expect("test");
}

#[test]
fn lease_reuse_true_allows_concurrent() {
    let auth = TokenAuthentication::from_accounts(sample_file()).expect("test");
    let snap = auth.snapshot_arc();
    let hash = token_hash(b"tok2");
    let acc = snap.by_token_hash.get(&hash).expect("test").account.clone();
    let g1 = auth.leases().try_lease_arc(&acc).expect("test");
    let g2 = auth.leases().try_lease_arc(&acc).expect("test");
    assert_eq!(auth.leases().active_count(&acc), 2);
    drop(g1);
    drop(g2);
    assert_eq!(auth.leases().active_count(&acc), 0);
}

#[test]
fn lease_cas_serializes_concurrent_attempts() {
    let auth = Arc::new(TokenAuthentication::from_accounts(sample_file()).expect("test"));
    let snap = auth.snapshot_arc();
    let hash = token_hash(b"tok1");
    let acc = snap.by_token_hash.get(&hash).expect("test").account.clone();

    let won = Arc::new(AtomicUsize::new(0));
    let conflict = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let leases = auth.leases().clone();
        let acc = acc.clone();
        let won = won.clone();
        let conflict = conflict.clone();
        handles.push(std::thread::spawn(move || {
            match leases.try_lease_arc(&acc) {
                Ok(g) => {
                    won.fetch_add(1, Ordering::SeqCst);
                    drop(g);
                }
                Err(LeaseError::Conflict) => {
                    conflict.fetch_add(1, Ordering::SeqCst);
                }
                Err(LeaseError::Exhausted) => {
                    panic!("unexpected Exhausted on reuse=false path");
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("test");
    }
    assert_eq!(
        won.load(Ordering::SeqCst) + conflict.load(Ordering::SeqCst),
        16
    );
    assert_eq!(auth.leases().active_count(&acc), 0);
}

#[test]
fn lease_per_account_ceiling_enforced() {
    let leases = Arc::new(LeaseTracker::with_max_per_account(3));
    let acc = Arc::new(Account {
        name: "u".into(),
        token: "t".into(),
        reuse: true,
        routes: vec![],
        allowed_ips: vec![],
    });
    let g1 = leases.try_lease_arc(&acc).expect("test");
    let _g2 = leases.try_lease_arc(&acc).expect("test");
    let _g3 = leases.try_lease_arc(&acc).expect("test");
    let r = leases.try_lease_arc(&acc);
    assert!(matches!(r, Err(LeaseError::Exhausted)));
    assert_eq!(leases.active_count(&acc), 3);
    drop(g1);
    let _g4 = leases.try_lease_arc(&acc).expect("test");
    assert_eq!(leases.active_count(&acc), 3);
}

#[test]
fn lease_release_garbage_collects_zero_entries() {
    let leases = Arc::new(LeaseTracker::new());
    let acc = Arc::new(Account {
        name: "u".into(),
        token: "tok-gc".into(),
        reuse: true,
        routes: vec![],
        allowed_ips: vec![],
    });
    let g = leases.try_lease_arc(&acc).expect("test");
    let h = token_hash(b"tok-gc");
    assert!(leases.active.contains_key(&h));
    drop(g);
    // After release, the entry should be GCed so reloads cannot leak.
    assert!(!leases.active.contains_key(&h));
}

#[test]
fn lease_survives_reload_when_token_unchanged() {
    // Two snapshots issuing fresh Arc<Account> with the same token must
    // resolve to the same lease slot.
    let snap1 = AccountsSnapshot::build(sample_file()).expect("test");
    let snap2 = AccountsSnapshot::build(sample_file()).expect("test");
    let h = token_hash(b"tok2");
    let acc1 = snap1.by_token_hash.get(&h).expect("test").account.clone();
    let acc2 = snap2.by_token_hash.get(&h).expect("test").account.clone();
    // They are distinct Arc allocations:
    assert!(!Arc::ptr_eq(&acc1, &acc2));

    let leases = Arc::new(LeaseTracker::new());
    let g1 = leases.try_lease_arc(&acc1).expect("test");
    // Release-via-acc2 path: hash-keyed tracker must observe count==1
    // for either Arc identity.
    assert_eq!(leases.active_count(&acc1), 1);
    assert_eq!(leases.active_count(&acc2), 1);
    let g2 = leases.try_lease_arc(&acc2).expect("test");
    assert_eq!(leases.active_count(&acc1), 2);
    drop(g1);
    drop(g2);
    assert_eq!(leases.active_count(&acc1), 0);
}

/// Smoke test for timing-attack invariance on the HashMap probe.
///
/// We don't claim ns-tight constant time — that would require disabling
/// CPU frequency scaling, isolating cores, and a microbenchmarking
/// harness. What we *do* claim: a random 32-byte input and a known-prefix
/// input both hit the same code path (BLAKE3 hash → HashMap miss →
/// return None) with no token-content-dependent branches before the miss.
/// This test is a sanity check that the order-of-magnitude is comparable.
#[test]
fn authenticate_timing_smoke() {
    use std::time::Instant;
    let snap = AccountsSnapshot::build(sample_file()).expect("test");
    let ip4 = ip("127.0.0.1");

    // Warm up.
    for _ in 0..10_000 {
        let _ = snap.authenticate("tok-no-match", "r", ip4);
        let _ = snap.authenticate("tok1prefix-extended-bytes-x", "r", ip4);
    }

    let n = 50_000;
    let t0 = Instant::now();
    for _ in 0..n {
        // Token close to a real one: same length, different content.
        let _ = snap.authenticate("tok9", "r", ip4);
    }
    let near_miss = t0.elapsed();

    let t1 = Instant::now();
    for _ in 0..n {
        // Token nothing like a real one.
        let _ = snap.authenticate("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "r", ip4);
    }
    let random_miss = t1.elapsed();

    // Tolerate a 5x ratio either direction. Lower bounds aren't meaningful
    // here — we're guarding against an order-of-magnitude regression
    // (e.g. accidentally adding a strncmp short-circuit before the hash).
    let ratio = near_miss.as_nanos() as f64 / random_miss.as_nanos() as f64;
    assert!(
        (0.2..=5.0).contains(&ratio),
        "near_miss={near_miss:?} random_miss={random_miss:?} ratio={ratio}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reload_swap_and_malformed_preserves_snapshot() {
    let mut tf = tempfile::NamedTempFile::new().expect("test");
    let yaml1 = r#"
accounts:
  - name: u1
    token: tok-old
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
    tf.write_all(yaml1.as_bytes()).expect("test");
    tf.flush().expect("test");

    let auth = TokenAuthentication::from_file(tf.path()).expect("test");
    let snap1 = auth.snapshot_arc();
    let h_old = token_hash(b"tok-old");
    let h_new = token_hash(b"tok-new");
    assert!(snap1.by_token_hash.contains_key(&h_old));
    assert!(!snap1.by_token_hash.contains_key(&h_new));

    let yaml2 = r#"
accounts:
  - name: u1
    token: tok-new
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
    std::fs::write(tf.path(), yaml2).expect("test");
    auth.reload().await;
    let snap2 = auth.snapshot_arc();
    assert!(snap2.by_token_hash.contains_key(&h_new));
    assert!(!snap2.by_token_hash.contains_key(&h_old));

    let same_reload_count = Arc::new(AtomicUsize::new(0));
    let same_dispatch = tracing::Dispatch::new(
        Registry::default().with(InfoEventCounter {
            count: Arc::clone(&same_reload_count),
        }),
    );
    let _guard = tracing::dispatcher::set_default(&same_dispatch);
    auth.reload().await;
    drop(_guard);
    let snap2_again = auth.snapshot_arc();
    assert!(Arc::ptr_eq(&snap2, &snap2_again));
    assert_eq!(same_reload_count.load(Ordering::Relaxed), 0);

    std::fs::write(tf.path(), b": : : not yaml").expect("test");
    auth.reload().await;
    let snap3 = auth.snapshot_arc();
    assert!(
        snap3.by_token_hash.contains_key(&h_new),
        "malformed reload must preserve previous snapshot"
    );

    let yaml_dup = r#"
accounts:
  - name: u1
    token: dup
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
  - name: u2
    token: dup
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
    std::fs::write(tf.path(), yaml_dup).expect("test");
    auth.reload().await;
    let snap4 = auth.snapshot_arc();
    assert!(
        snap4.by_token_hash.contains_key(&h_new),
        "duplicate-token reload must preserve previous snapshot"
    );
    assert!(!snap4.by_token_hash.contains_key(&token_hash(b"dup")));
}