//! Global probe rate limiter (token bucket).

use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Shared rate limiter: max `pps` probes per second.
/// `None` / zero pps = unlimited.
#[derive(Debug)]
pub struct RateLimiter {
    inner: Option<Mutex<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    pps: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn unlimited() -> Self {
        Self { inner: None }
    }

    pub fn per_second(pps: u64) -> Self {
        if pps == 0 {
            return Self::unlimited();
        }
        Self {
            inner: Some(Mutex::new(Bucket {
                pps: pps as f64,
                tokens: pps as f64,
                last: Instant::now(),
            })),
        }
    }

    pub fn is_limited(&self) -> bool {
        self.inner.is_some()
    }

    /// Async acquire one probe slot (connect path).
    pub async fn acquire(&self) {
        loop {
            if let Some(wait) = self.try_take() {
                if wait.is_zero() {
                    return;
                }
                sleep(wait).await;
            } else {
                return;
            }
        }
    }

    /// Blocking acquire (SYN path on worker thread).
    pub fn acquire_blocking(&self) {
        loop {
            if let Some(wait) = self.try_take() {
                if wait.is_zero() {
                    return;
                }
                std::thread::sleep(wait.max(Duration::from_micros(50)));
            } else {
                return;
            }
        }
    }

    /// Returns `None` if unlimited, `Some(Duration::ZERO)` if token taken,
    /// or `Some(wait)` if need to sleep.
    fn try_take(&self) -> Option<Duration> {
        let guard = self.inner.as_ref()?;
        let mut b = guard.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * b.pps).min(b.pps);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Some(Duration::ZERO)
        } else {
            let need = 1.0 - b.tokens;
            let secs = need / b.pps;
            Some(Duration::from_secs_f64(secs.max(0.000_05)))
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_blocks() {
        let r = RateLimiter::unlimited();
        for _ in 0..100 {
            assert!(r.try_take().is_none());
        }
    }

    #[test]
    fn limited_eventually_waits() {
        let r = RateLimiter::per_second(10);
        let mut waits = 0;
        for _ in 0..30 {
            if let Some(d) = r.try_take() {
                if !d.is_zero() {
                    waits += 1;
                }
            }
        }
        assert!(waits > 0, "expected some waits under 10 pps");
    }
}
