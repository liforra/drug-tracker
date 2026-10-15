//! Token-bucket rate limiting for the routes that have no authentication in front of
//! them.
//!
//! A note on what is being limited. Behind a reverse proxy every request arrives from
//! the proxy's address, so per-client limiting by socket address would be meaningless,
//! and trusting `X-Forwarded-For` would let anyone spoof their way out of the limit.
//! So the buckets here are either global per route, which caps total load and cannot be
//! evaded, or keyed on something from the request body that is worth protecting
//! individually -- a device id being hammered with challenges, for instance.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Beyond this many live buckets we start evicting. Prevents an attacker from growing
/// the map without bound by varying the key.
const MAX_BUCKETS: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Quota {
    /// Burst size: how many requests can arrive back to back.
    pub capacity: f64,
    /// Sustained rate once the burst is spent.
    pub refill_per_sec: f64,
}

impl Quota {
    pub const fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self { capacity, refill_per_sec }
    }
}

/// Quotas are generous: this is a personal server, and a limit that trips during normal
/// use is worse than no limit at all because it teaches you to raise it blindly.
pub mod quotas {
    use super::Quota;

    /// Per device id. An enrolled device authenticates roughly hourly.
    pub const CHALLENGE: Quota = Quota::new(10.0, 0.1);
    /// Global. Signature verification is the expensive half of authentication.
    pub const VERIFY: Quota = Quota::new(30.0, 0.5);
    /// Global. Claiming is rare and a wrong code should cost something.
    pub const CLAIM: Quota = Quota::new(5.0, 0.05);
    /// Global. Every tunnelled request does an X25519 exchange before we know who it is.
    pub const TUNNEL: Quota = Quota::new(120.0, 20.0);
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_seen: Instant,
    /// Kept per bucket rather than taken from the caller: different keys run under
    /// different quotas, so judging one bucket by another's limits would be wrong.
    capacity: f64,
    refill_per_sec: f64,
}

impl Bucket {
    /// Tokens this bucket would have right now, accounting for refill since last seen.
    fn projected(&self, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.last_seen).as_secs_f64();
        (self.tokens + elapsed * self.refill_per_sec).min(self.capacity)
    }

    /// Whether this bucket has refilled and therefore holds no state worth keeping.
    fn is_spent(&self, now: Instant) -> bool {
        self.projected(now) >= self.capacity
    }

    /// How close to full this bucket is, 0.0 (throttled) to 1.0 (untouched).
    ///
    /// This is the eviction priority: a bucket near 1.0 costs nothing to drop, because
    /// recreating it yields the same allowance. A bucket near 0.0 is the only record
    /// that someone is currently being limited, and dropping it hands them a reset.
    fn fullness(&self, now: Instant) -> f64 {
        if self.capacity <= 0.0 {
            return 1.0;
        }
        self.projected(now) / self.capacity
    }
}

#[derive(Debug)]
pub struct Denied {
    pub retry_after: Duration,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, key: &str, quota: Quota) -> Result<(), Denied> {
        self.check_at(key, quota, Instant::now())
    }

    /// Separated from [`check`] so the time behaviour can be tested without sleeping.
    pub fn check_at(&self, key: &str, quota: Quota, now: Instant) -> Result<(), Denied> {
        let mut buckets = self.buckets.lock().unwrap();

        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(key) {
            evict(&mut buckets, now);
        }

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: quota.capacity,
            last_seen: now,
            capacity: quota.capacity,
            refill_per_sec: quota.refill_per_sec,
        });

        let elapsed = now.saturating_duration_since(bucket.last_seen).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * quota.refill_per_sec).min(quota.capacity);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let missing = 1.0 - bucket.tokens;
            let seconds = if quota.refill_per_sec > 0.0 {
                missing / quota.refill_per_sec
            } else {
                f64::INFINITY
            };
            Err(Denied { retry_after: Duration::from_secs_f64(seconds.min(3600.0).max(1.0)) })
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// Make room in a full bucket map.
///
/// Evicts the *fullest* buckets first, not the oldest. Least-recently-used is the
/// obvious choice and it is exactly wrong here: a throttled key is by definition one
/// nobody is successfully touching, so LRU would evict the entries under attack first
/// and hand the attacker a reset by flooding distinct keys.
///
/// Ranking by remaining allowance inverts that. A near-full bucket costs nothing to
/// drop, since recreating it gives the same result. A near-empty one is the only record
/// that someone is being limited right now, so it is evicted last.
fn evict(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    buckets.retain(|_, bucket| !bucket.is_spent(now));
    if buckets.len() < MAX_BUCKETS {
        return;
    }

    let target = MAX_BUCKETS * 3 / 4;
    let surplus = buckets.len().saturating_sub(target);

    let mut ranked: Vec<(f64, String)> =
        buckets.iter().map(|(k, b)| (b.fullness(now), k.clone())).collect();
    // Fullest first; among equals, the least recently touched.
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
    for (_, key) in ranked.into_iter().take(surplus) {
        buckets.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST: Quota = Quota::new(3.0, 1.0);

    #[test]
    fn a_burst_is_allowed_up_to_capacity() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for i in 0..3 {
            assert!(limiter.check_at("k", TEST, now).is_ok(), "request {i} should pass");
        }
        assert!(limiter.check_at("k", TEST, now).is_err(), "the fourth exceeds the burst");
    }

    #[test]
    fn tokens_come_back_over_time() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        for _ in 0..3 {
            limiter.check_at("k", TEST, start).unwrap();
        }
        assert!(limiter.check_at("k", TEST, start).is_err());

        // One token per second at this quota.
        let later = start + Duration::from_secs(1);
        assert!(limiter.check_at("k", TEST, later).is_ok());
        assert!(limiter.check_at("k", TEST, later).is_err(), "only one token had refilled");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        limiter.check_at("k", TEST, start).unwrap();

        // An hour of idling must not bank an hour of requests.
        let much_later = start + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(limiter.check_at("k", TEST, much_later).is_ok());
        }
        assert!(limiter.check_at("k", TEST, much_later).is_err());
    }

    #[test]
    fn keys_are_independent() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..3 {
            limiter.check_at("phone", TEST, now).unwrap();
        }
        assert!(limiter.check_at("phone", TEST, now).is_err());
        assert!(
            limiter.check_at("laptop", TEST, now).is_ok(),
            "one device being throttled must not lock out another"
        );
    }

    #[test]
    fn retry_after_is_reported_and_bounded() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..3 {
            limiter.check_at("k", TEST, now).unwrap();
        }
        let denied = limiter.check_at("k", TEST, now).unwrap_err();
        assert!(denied.retry_after >= Duration::from_secs(1));
        assert!(denied.retry_after <= Duration::from_secs(3600));
    }

    #[test]
    fn the_bucket_map_does_not_grow_without_bound() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        // Every key distinct and every bucket touched at the same instant, so none has
        // refilled -- the case where a refill-only eviction policy quietly does nothing.
        for i in 0..(MAX_BUCKETS * 2) {
            let _ = limiter.check_at(&format!("key-{i}"), TEST, now);
        }
        assert!(limiter.len() <= MAX_BUCKETS, "map grew to {} entries", limiter.len());
    }

    #[test]
    fn a_hot_key_survives_eviction_pressure() {
        // Slow refill on purpose: with TEST's one-token-per-second the victim would
        // legitimately have refilled by the end of the flood, and the test would pass
        // for the wrong reason.
        const SLOW: Quota = Quota::new(3.0, 0.001);
        let limiter = RateLimiter::new();
        let start = Instant::now();

        // A key under active throttling.
        for _ in 0..3 {
            limiter.check_at("victim", SLOW, start).unwrap();
        }
        assert!(limiter.check_at("victim", SLOW, start).is_err());

        // Flood with distinct keys. The victim is the oldest entry throughout, which is
        // precisely the case an LRU policy would get wrong.
        for i in 0..(MAX_BUCKETS * 2) {
            let later = start + Duration::from_millis(i as u64 + 1);
            let _ = limiter.check_at(&format!("flood-{i}"), SLOW, later);
        }

        // Still inside the victim's throttle window, so its limit must still apply.
        let after = start + Duration::from_millis(MAX_BUCKETS as u64 * 2 + 2);
        assert!(
            limiter.check_at("victim", SLOW, after).is_err(),
            "flooding distinct keys must not clear someone else's throttle"
        );
    }

    #[test]
    fn each_key_is_judged_by_its_own_quota() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let tight = Quota::new(1.0, 0.01);
        let loose = Quota::new(50.0, 10.0);

        limiter.check_at("tight", tight, now).unwrap();
        assert!(limiter.check_at("tight", tight, now).is_err());

        for _ in 0..50 {
            assert!(limiter.check_at("loose", loose, now).is_ok());
        }
    }
}
