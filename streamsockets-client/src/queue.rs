//! Bounded byte-capped frame queue with drop-oldest semantics.

use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Debug)]
pub struct ReconnectQueue {
    inner: VecDeque<Bytes>,
    cap_bytes: u64,
    cur_bytes: u64,
    pub dropped_overflow: u64,
}

impl ReconnectQueue {
    pub fn new(cap_bytes: u64) -> Self {
        Self {
            inner: VecDeque::new(),
            cap_bytes,
            cur_bytes: 0,
            dropped_overflow: 0,
        }
    }

    pub fn len_bytes(&self) -> u64 {
        self.cur_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push a frame. If exceeding cap, drops oldest until it fits. Returns
    /// the number of frames dropped to make room.
    pub fn push(&mut self, frame: Bytes) -> usize {
        let mut dropped = 0usize;
        let frame_len = frame.len() as u64;
        if frame_len > self.cap_bytes {
            // Single frame larger than cap — drop it entirely.
            self.dropped_overflow += 1;
            return 1;
        }
        while self.cur_bytes + frame_len > self.cap_bytes {
            if let Some(old) = self.inner.pop_front() {
                self.cur_bytes -= old.len() as u64;
                dropped += 1;
                self.dropped_overflow += 1;
            } else {
                break;
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
