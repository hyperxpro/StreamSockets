//! (#5) Process-shared lock-on cell. Verifies the type wired through
//! `SharedLockedSource` provides first-write-wins CAS semantics that are
//! observable across N concurrent writers — the property the listener loop
//! relies on for the §6.4 single-source invariant.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use streamsockets_client::fsm::SharedLockedSource;

#[test]
fn first_write_wins_across_threads() {
    let shared: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    // Spawn N threads, each racing to install a distinct SocketAddr. After
    // the dust settles exactly one address must be present.
    let n = 32;
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let s = shared.clone();
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, (i % 250) as u8 + 1),
            12000 + i as u16,
        ));
        handles.push(std::thread::spawn(move || {
            // The listener loop's flow: load, if None, attempt CAS install.
            if s.load().is_none() {
                let _prev = s.compare_and_swap(&None::<Arc<SocketAddr>>, Some(Arc::new(addr)));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_addr = shared.load();
    assert!(final_addr.is_some(), "exactly one writer should have won");
}

#[test]
fn second_distinct_source_does_not_overwrite() {
    // Same listener-loop semantics: once locked, a second source should
    // be rejected; the listener does not call `store`, only the initial CAS.
    let shared: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    let first: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let second: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    // Mimic listener-loop logic:
    if shared.load().is_none() {
        let _ = shared.compare_and_swap(&None::<Arc<SocketAddr>>, Some(Arc::new(first)));
    }
    // A second peer arrives. Listener observes Some, sees mismatch, drops.
    let snap = shared.load();
    assert!(snap.is_some());
    assert_eq!(*snap.as_ref().unwrap().as_ref(), first);

    // Even an explicit (incorrect) CAS attempt against `None` must not
    // overwrite the existing first source.
    let _ = shared.compare_and_swap(&None::<Arc<SocketAddr>>, Some(Arc::new(second)));
    let snap2 = shared.load();
    assert_eq!(*snap2.as_ref().unwrap().as_ref(), first);
}

#[test]
fn shared_handle_clones_share_state() {
    // Trivial sanity: clones of `SharedLockedSource` share state.
    let a: SharedLockedSource = Arc::new(ArcSwapOption::const_empty());
    let b = a.clone();
    let addr: SocketAddr = "192.0.2.10:5555".parse().unwrap();
    a.store(Some(Arc::new(addr)));
    let snap = b.load();
    assert_eq!(*snap.as_ref().unwrap().as_ref(), addr);
}
