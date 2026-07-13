use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct RateLimiter {
    inner: Arc<Mutex<LimiterInner>>,
}

struct LimiterInner {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
    consecutive_failures: u64,
    consecutive_successes: u64,
    min_delay: Duration,
    base_delay: Duration,
    backoff_factor: f64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LimiterInner {
                tokens: burst,
                max_tokens: burst,
                refill_rate: rate_per_sec,
                last_refill: Instant::now(),
                consecutive_failures: 0,
                consecutive_successes: 0,
                min_delay: Duration::from_millis(10),
                base_delay: Duration::from_millis(100),
                backoff_factor: 1.5,
            })),
        }
    }

    pub async fn acquire(&self) -> Duration {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last_refill).as_secs_f64();
        inner.tokens = (inner.tokens + elapsed * inner.refill_rate).min(inner.max_tokens);
        inner.last_refill = now;

        if inner.tokens >= 1.0 {
            inner.tokens -= 1.0;
            Duration::ZERO
        } else {
            let wait = Duration::from_secs_f64((1.0 - inner.tokens) / inner.refill_rate);
            inner.tokens = 0.0;
            wait + inner.base_delay
        }
    }

    pub async fn report_success(&self) {
        let mut inner = self.inner.lock().await;
        inner.consecutive_successes += 1;
        inner.consecutive_failures = 0;
        if inner.consecutive_successes >= 5 {
            inner.backoff_factor = (inner.backoff_factor - 0.05).max(1.0);
            inner.consecutive_successes = 0;
        }
    }

    pub async fn report_failure(&self) {
        let mut inner = self.inner.lock().await;
        inner.consecutive_failures += 1;
        inner.consecutive_successes = 0;
        if inner.consecutive_failures >= 3 {
            inner.backoff_factor = (inner.backoff_factor + 0.25).min(5.0);
            inner.consecutive_failures = 0;
        }
        inner.base_delay = Duration::from_secs_f64(
            inner.base_delay.as_secs_f64() * inner.backoff_factor
        ).max(inner.min_delay);
    }

    pub async fn reset(&self) {
        let mut inner = self.inner.lock().await;
        inner.tokens = inner.max_tokens;
        inner.base_delay = Duration::from_millis(100);
        inner.backoff_factor = 1.5;
        inner.consecutive_failures = 0;
        inner.consecutive_successes = 0;
    }
}
