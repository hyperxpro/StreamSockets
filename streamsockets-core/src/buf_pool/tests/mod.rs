use super::*;

#[test]
fn acquire_returns_full_capacity_buf() {
    let pool = BufPool::new(4, 1024);
    let buf = pool.acquire();
    assert_eq!(buf.capacity(), 1024);
}

#[test]
fn drop_returns_to_pool() {
    let pool = BufPool::new(4, 1024);
    assert_eq!(pool.idle_count(), 0);
    let buf = pool.acquire();
    assert_eq!(pool.idle_count(), 0);
    drop(buf);
    assert_eq!(pool.idle_count(), 1);
}

#[test]
fn pool_capacity_caps_retained_buffers() {
    let pool = BufPool::new(2, 16);
    let bufs: Vec<_> = (0..5).map(|_| pool.acquire()).collect();
    for b in bufs {
        drop(b);
    }
    // soft cap = 2; rest get GC'd
    assert_eq!(pool.idle_count(), 2);
}

#[test]
fn buf_survives_pool_drop() {
    let pool = BufPool::new(2, 16);
    let mut buf = pool.acquire();
    drop(pool);
    // Buf still owns its allocation; mutating it must not panic.
    buf.as_mut()[0] = 7;
    assert_eq!(buf.as_ref()[0], 7);
    // Drop is a no-op now (Weak fails to upgrade).
}

#[test]
fn freeze_returns_bytes_with_return_on_drop() {
    let pool = BufPool::new(2, 32);
    {
        let mut buf = pool.acquire();
        buf.as_mut()[..5].copy_from_slice(b"hello");
        let bytes = buf.freeze(5).expect("freeze fits");
        assert_eq!(&bytes[..], b"hello");
        // Pool has zero idle while bytes is alive (the BufHandle is owned by
        // the inner Bytes refcount).
        assert_eq!(pool.idle_count(), 0);
        // Cloning the Bytes shares the same allocation: still no return.
        let clone = bytes.clone();
        assert_eq!(pool.idle_count(), 0);
        drop(clone);
        assert_eq!(pool.idle_count(), 0);
        drop(bytes);
    }
    assert_eq!(pool.idle_count(), 1, "freeze().drop() returns to pool");
}

#[test]
fn freeze_oversize_returns_error() {
    let pool = BufPool::new(1, 8);
    let buf = pool.acquire();
    let err = buf.freeze(99).expect_err("oversize must error");
    assert_eq!(
        err,
        FreezeError::OversizedLength {
            len: 99,
            capacity: 8
        }
    );
    // The error case still consumed the handle; the buffer is gone here
    // but the inner Vec dropped (no pool return because the handle is
    // moved into Bytes::from_owner only on the success path).
}

#[test]
fn freeze_error_drops_handle_to_pool() {
    // Sanity: the handle is consumed by-value; on the error path it is
    // simply dropped, returning the underlying buffer to the pool.
    let pool = BufPool::new(1, 8);
    assert_eq!(pool.idle_count(), 0);
    {
        let buf = pool.acquire();
        let _ = buf.freeze(99);
    }
    assert_eq!(pool.idle_count(), 1, "errored freeze still recycles buf");
}
