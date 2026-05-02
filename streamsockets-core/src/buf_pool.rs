//! Per-worker buffer pool for UDP recv.
//!
//! Each worker holds a fixed-size pool (default 1024 × 64 KiB per MIGRATION.md §4).
//! On the io_uring path the buffers are registered with `IORING_REGISTER_BUFFERS`
//! at startup so the kernel skips `get_user_pages` per recv. On the epoll path
//! the same pool eliminates per-recv heap traffic.
//!
//! `BufHandle` returns its underlying allocation to the pool on drop. When the
//! handle is split into `Bytes` slices via [`BufHandle::freeze`], the same
//! return-on-last-drop semantics are preserved through a custom `bytes::Vtable`
//! (added in milestone 3 alongside the io_uring impl).

use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;

/// Default buffer size: 64 KiB, matching `MAX_FRAME_SIZE * 2` headroom for GRO
/// coalescing.
pub const DEFAULT_BUF_SIZE: usize = 64 * 1024;

/// Default pool capacity (1024 buffers × 64 KiB ≈ 64 MiB resident per worker).
pub const DEFAULT_POOL_CAPACITY: usize = 1024;

/// A pool of fixed-size byte buffers shared by one worker's UDP path.
///
/// Cloning a `BufPool` shares the underlying free-list (it's an `Arc` inside).
#[derive(Clone)]
pub struct BufPool {
    inner: Arc<BufPoolInner>,
}

struct BufPoolInner {
    free: Mutex<Vec<Vec<u8>>>,
    buf_size: usize,
    capacity: usize,
}

impl BufPool {
    /// Create a new pool of `capacity` buffers, each `buf_size` bytes long.
    /// Buffers are allocated lazily on first acquire.
    #[must_use]
    pub fn new(capacity: usize, buf_size: usize) -> Self {
        Self {
            inner: Arc::new(BufPoolInner {
                free: Mutex::new(Vec::with_capacity(capacity)),
                buf_size,
                capacity,
            }),
        }
    }

    /// Convenience: pool sized per spec (1024 × 64 KiB).
    #[must_use]
    pub fn default_for_worker() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY, DEFAULT_BUF_SIZE)
    }

    /// Acquire a buffer. If the free-list is empty, a fresh allocation is made
    /// (mimalloc'd on production builds). Capacity is a soft target: under heavy
    /// burst we allocate above it; the pool only retains up to `capacity` on drop.
    #[must_use]
    pub fn acquire(&self) -> BufHandle {
        let mut buf = {
            let mut free = self.inner.free.lock();
            free.pop()
        }
        .unwrap_or_else(|| vec![0u8; self.inner.buf_size]);
        if buf.len() < self.inner.buf_size {
            buf.resize(self.inner.buf_size, 0);
        }
        BufHandle {
            inner: Some(buf),
            pool: Arc::downgrade(&self.inner),
        }
    }

    /// Buffer size of every buffer in this pool.
    #[must_use]
    pub fn buf_size(&self) -> usize {
        self.inner.buf_size
    }

    /// Number of buffers currently sitting in the free list.
    #[must_use]
    pub fn idle_count(&self) -> usize {
        self.inner.free.lock().len()
    }
}

/// A buffer borrowed from a [`BufPool`]. Returns to the pool on drop, unless the
/// pool has already been dropped.
pub struct BufHandle {
    inner: Option<Vec<u8>>,
    pool: std::sync::Weak<BufPoolInner>,
}

impl BufHandle {
    /// Mutable view of the entire buffer (always at full capacity).
    #[must_use]
    pub fn as_mut(&mut self) -> &mut [u8] {
        self.inner
            .as_mut()
            .expect("BufHandle inner is Some until drop")
            .as_mut_slice()
    }

    /// Immutable view of the entire buffer.
    #[must_use]
    pub fn as_ref(&self) -> &[u8] {
        self.inner
            .as_ref()
            .expect("BufHandle inner is Some until drop")
            .as_slice()
    }

    /// Capacity of this buffer in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.as_ref().map(Vec::len).unwrap_or(0)
    }

    /// Convert this handle into a `Bytes` slice of length `len`, preserving the
    /// return-to-pool-on-last-drop semantics. Backed by [`Bytes::from_owner`],
    /// which ships in `bytes >= 1.7` and is the documented stable hook for a
    /// pool-aware `Bytes` (replaces the previous handcrafted `bytes::Vtable`
    /// approach mentioned in older drafts of MIGRATION.md §7.3).
    ///
    /// Returns [`FreezeError::OversizedLength`] when `len > capacity`. The
    /// length argument is typically kernel-derived (`recvmsg` wire length); in
    /// release builds we run with `panic = "abort"`, so an `assert!` here
    /// would terminate the process before structured logging gets a chance to
    /// flush. Callers must drop the frame and bump a counter instead.
    pub fn freeze(self, len: usize) -> Result<Bytes, FreezeError> {
        let cap = self.capacity();
        if len > cap {
            return Err(FreezeError::OversizedLength { len, capacity: cap });
        }
        // Bytes::from_owner accepts T: AsRef<[u8]> + Send + 'static. Our
        // BufHandle satisfies both: AsRef<[u8]> below; Send because the inner
        // Vec<u8> + Weak<...> are both Send.
        let full = Bytes::from_owner(self);
        Ok(full.slice(..len))
    }
}

/// Error returned by [`BufHandle::freeze`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeError {
    /// `len` exceeded the buffer's capacity. The handle is consumed; the
    /// underlying allocation returns to the pool on drop. Caller should
    /// log + bump a counter and discard the frame.
    OversizedLength {
        /// The requested length.
        len: usize,
        /// The buffer's actual capacity.
        capacity: usize,
    },
}

impl std::fmt::Display for FreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OversizedLength { len, capacity } => {
                write!(f, "freeze len {len} exceeds buffer capacity {capacity}")
            }
        }
    }
}

impl std::error::Error for FreezeError {}

impl AsRef<[u8]> for BufHandle {
    fn as_ref(&self) -> &[u8] {
        BufHandle::as_ref(self)
    }
}

impl Drop for BufHandle {
    fn drop(&mut self) {
        let Some(buf) = self.inner.take() else { return };
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        let mut free = pool.free.lock();
        if free.len() < pool.capacity {
            free.push(buf);
        }
        // else drop the buf — pool already at soft capacity.
    }
}

#[cfg(test)]
mod tests {
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
}
