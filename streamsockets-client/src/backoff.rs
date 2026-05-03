//! Decorrelated jitter exponential backoff (Marc Brooker / AWS).
//!
//! `next = min(cap, rand_between(base, prev * 3))`.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    prev: Duration,
}

impl Backoff {
    /// Construct. Panics if `cap < base` — that combination produces a
    /// silently-stuck retry loop where every sample is clamped to `cap`,
    /// the curve never grows, and the operator's intended max-delay is
    /// effectively the *min* delay. Fail-fast at construction.
    pub fn new(base: Duration, cap: Duration) -> Self {
        assert!(cap >= base, "Backoff: cap {cap:?} must be >= base {base:?}");
        Self {
            base,
            cap,
            prev: base,
        }
    }

    /// Fallible constructor; same semantics as `new` but returns an error
    /// instead of panicking. Useful from `validate()` paths.
    pub fn try_new(base: Duration, cap: Duration) -> Result<Self, &'static str> {
        if cap < base {
            return Err("Backoff: cap must be >= base");
        }
        Ok(Self {
            base,
            cap,
            prev: base,
        })
    }

    /// Sample the next delay. Mutates internal state.
    pub fn next_delay(&mut self) -> Duration {
        let mut rng = rand::thread_rng();
        let upper_ms = (self.prev.as_millis() as u64).saturating_mul(3);
        let upper_ms = upper_ms.max(self.base.as_millis() as u64 + 1);
        let lo = self.base.as_millis() as u64;
        let hi = upper_ms;
        let pick_ms = if hi <= lo { lo } else { rng.gen_range(lo..hi) };
        let cap_ms = self.cap.as_millis() as u64;
        let final_ms = pick_ms.min(cap_ms.max(lo));
        self.prev = Duration::from_millis(final_ms);
        self.prev
    }

    /// Reset to base — call on transition to Live.
    pub fn reset(&mut self) {
        self.prev = self.base;
    }
}

#[cfg(test)]
mod tests;
