//! Bounded byte- AND packet-capped frame queue with drop-oldest semantics.
//!
//! Two independent caps are enforced: `cap_bytes` and `cap_packets`. On push,
//! whichever cap would be exceeded first triggers FIFO eviction of older
//! frames until both caps would accept the new frame. This pairs the existing
//! byte budget (memory ceiling) with a packet budget (staleness ceiling): on
//! a UDP tunnel carrying many small packets, 1 MiB at 200 B average is ~5000
//! buffered frames — far more than is useful, since stale UDP is almost
//! always discarded by the application. A small packet cap (default 32 via
//! `QUEUE_MAX_PACKETS`) keeps the replay set fresh on reconnect.

use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Debug)]
pub struct ReconnectQueue {
    inner: VecDeque<Bytes>,
    cap_bytes: u64,
    cap_packets: usize,
    cur_bytes: u64,
    pub dropped_overflow: u64,
}

impl ReconnectQueue {
    pub fn new(cap_bytes: u64, cap_packets: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            cap_bytes,
            cap_packets,
            cur_bytes: 0,
            dropped_overflow: 0,
        }
    }

    pub fn len_bytes(&self) -> u64 {
        self.cur_bytes
    }

    pub fn len_packets(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push a frame. FIFO; drops oldest until BOTH byte and packet caps fit.
    /// Returns the number of frames dropped to make room. `cap_packets == 0`
    /// disables the queue entirely (every push is dropped on the floor).
    pub fn push(&mut self, frame: Bytes) -> usize {
        let frame_len = frame.len() as u64;
        // A single frame larger than the byte cap is dropped outright.
        if frame_len > self.cap_bytes {
            self.dropped_overflow += 1;
            return 1;
        }
        // cap_packets == 0 means the queue is disabled.
        if self.cap_packets == 0 {
            self.dropped_overflow += 1;
            return 1;
        }

        let mut dropped = 0usize;
        // Evict oldest until BOTH caps would accept the new frame.
        while self.cur_bytes + frame_len > self.cap_bytes || self.inner.len() + 1 > self.cap_packets
        {
            match self.inner.pop_front() {
                Some(old) => {
                    self.cur_bytes -= old.len() as u64;
                    dropped += 1;
                    self.dropped_overflow += 1;
                }
                None => break,
            }
        }
        self.cur_bytes += frame_len;
        self.inner.push_back(frame);
        dropped
    }

    pub fn pop_front(&mut self) -> Option<Bytes> {
        let frame = self.inner.pop_front()?;
        self.cur_bytes -= frame.len() as u64;
        Some(frame)
    }

    /// Purge the entire queue. Returns the number of frames dropped.
    pub fn purge(&mut self) -> usize {
        let n = self.inner.len();
        self.inner.clear();
        self.cur_bytes = 0;
        n
    }
}

#[cfg(test)]
mod tests;
