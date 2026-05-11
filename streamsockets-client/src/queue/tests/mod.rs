use super::*;

#[test]
fn drop_oldest_at_byte_cap() {
    // Effectively unlimited packet cap so byte cap dominates.
    let mut q = ReconnectQueue::new(10, usize::MAX);
    q.push(Bytes::from_static(b"abcde")); // 5
    q.push(Bytes::from_static(b"fghij")); // 5, total 10
    let dropped = q.push(Bytes::from_static(b"klmno")); // would be 15
    assert_eq!(dropped, 1);
    assert_eq!(q.len_bytes(), 10);
    assert_eq!(q.pop_front().expect("test"), Bytes::from_static(b"fghij"));
    assert_eq!(q.pop_front().expect("test"), Bytes::from_static(b"klmno"));
}

#[test]
fn purge_clears_all() {
    let mut q = ReconnectQueue::new(100, usize::MAX);
    for _ in 0..5 {
        q.push(Bytes::from_static(b"hi"));
    }
    let n = q.purge();
    assert_eq!(n, 5);
    assert!(q.is_empty());
}

#[test]
fn packet_cap_evicts_oldest() {
    let mut q = ReconnectQueue::new(u64::MAX, 3);
    q.push(Bytes::from_static(b"a"));
    q.push(Bytes::from_static(b"b"));
    q.push(Bytes::from_static(b"c"));
    q.push(Bytes::from_static(b"d"));
    assert_eq!(q.len_packets(), 3);
    assert_eq!(q.pop_front().unwrap(), Bytes::from_static(b"b"));
    assert_eq!(q.pop_front().unwrap(), Bytes::from_static(b"c"));
    assert_eq!(q.pop_front().unwrap(), Bytes::from_static(b"d"));
}

#[test]
fn fifo_order_preserved_under_eviction() {
    let mut q = ReconnectQueue::new(u64::MAX, 2);
    for i in 0..10u8 {
        q.push(Bytes::copy_from_slice(&[i]));
    }
    // Newest two only, in order.
    assert_eq!(q.pop_front().unwrap()[..], [8]);
    assert_eq!(q.pop_front().unwrap()[..], [9]);
    assert!(q.pop_front().is_none());
}

#[test]
fn zero_packet_cap_disables_queue() {
    let mut q = ReconnectQueue::new(u64::MAX, 0);
    let dropped = q.push(Bytes::from_static(b"x"));
    assert_eq!(dropped, 1);
    assert!(q.is_empty());
    assert_eq!(q.dropped_overflow, 1);
}

#[test]
fn whichever_cap_hits_first_evicts() {
    // Byte cap dominates: cap=4 bytes, packet cap large.
    let mut q = ReconnectQueue::new(4, 1000);
    q.push(Bytes::from_static(b"aa"));
    q.push(Bytes::from_static(b"bb"));
    q.push(Bytes::from_static(b"cc"));
    assert_eq!(q.len_bytes(), 4);
    assert_eq!(q.len_packets(), 2);

    // Packet cap dominates: cap_packets=2, byte cap large.
    let mut q = ReconnectQueue::new(u64::MAX, 2);
    q.push(Bytes::from_static(b"a"));
    q.push(Bytes::from_static(b"b"));
    q.push(Bytes::from_static(b"c"));
    assert_eq!(q.len_packets(), 2);
    assert_eq!(q.pop_front().unwrap(), Bytes::from_static(b"b"));
}
