use super::*;

#[test]
fn drop_oldest_at_cap() {
    let mut q = ReconnectQueue::new(10);
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
    let mut q = ReconnectQueue::new(100);
    for _ in 0..5 {
        q.push(Bytes::from_static(b"hi"));
    }
    let n = q.purge();
    assert_eq!(n, 5);
    assert!(q.is_empty());
}
