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
mod tests {
    use super::*;

    #[test]
    fn capped_at_max() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        for _ in 0..50 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(30));
        }
    }

    #[test]
    fn distribution_jittered_10k_samples() {
        // Spec §11.1: "verify decorrelated jitter distribution (10K samples in expected range)".
        // We model the analytical decorrelated-jitter PDF: each sample is uniform
        // in [base, prev*3] then capped at 30s. After many iterations the sample
        // distribution should be (a) bounded by [base, cap], (b) heavy-tailed but
        // not degenerate, (c) at least N distinct buckets.
        let base = 100u128;
        let cap = 30_000u128;
        let mut b = Backoff::new(
            Duration::from_millis(base as u64),
            Duration::from_millis(cap as u64),
        );
        let mut samples = Vec::with_capacity(10_000);
        for _ in 0..10_000 {
            samples.push(b.next_delay().as_millis());
        }

        // (a) Strict bounds.
        let min = *samples.iter().min().expect("test");
        let max = *samples.iter().max().expect("test");
        assert!(min >= base, "min < base: {min}");
        assert!(max <= cap, "max > cap: {max}");

        // (b) Bucket the samples into 30 1-second buckets [0..1000, 1000..2000, ...].
        // Decorrelated jitter at scale should populate many buckets — assert ≥10.
        let mut buckets = [0u32; 30];
        for s in &samples {
            let idx = ((*s) / 1000).min(29) as usize;
            buckets[idx] += 1;
        }
        let nonempty = buckets.iter().filter(|&&n| n > 0).count();
        assert!(
            nonempty >= 10,
            "expected ≥10 of 30 buckets populated; got {nonempty}: {buckets:?}"
        );

        // (c) The tail sample (last element) should reach the cap eventually.
        // After 10K iterations max should be within 1% of cap.
        assert!(
            max as f64 >= cap as f64 * 0.99,
            "max sample {max} did not approach cap {cap}"
        );
    }

    #[test]
    #[should_panic(expected = "must be >= base")]
    fn cap_below_base_panics() {
        // (Fix #15) cap < base must be rejected at construction.
        let _ = Backoff::new(Duration::from_secs(10), Duration::from_secs(1));
    }

    #[test]
    fn try_new_rejects_cap_below_base() {
        assert!(Backoff::try_new(Duration::from_secs(10), Duration::from_secs(1)).is_err());
        assert!(Backoff::try_new(Duration::from_secs(1), Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        for _ in 0..10 {
            let _ = b.next_delay();
        }
        b.reset();
        // After reset the next sample should fall in [base, base*3)
        let next = b.next_delay();
        assert!(next.as_millis() >= 100);
        assert!(next.as_millis() < 300 || next == Duration::from_millis(100));
    }
}
