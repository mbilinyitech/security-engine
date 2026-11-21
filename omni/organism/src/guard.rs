//! Failure containment: a circuit breaker and a token-bucket rate limiter.
//!
//! Both are fail-closed. A breaker that has tripped refuses work until its
//! cooldown expires; a limiter that has no tokens refuses the request. Neither
//! guesses, and neither silently allows on error.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreakerStatus {
    pub state: BreakerState,
    pub failures: u32,
    pub opened_at_ms: Option<i64>,
    pub allowed: bool,
}

pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown_ms: i64,
    half_open_successes: u32,
    failures: u32,
    successes_in_half_open: u32,
    state: BreakerState,
    opened_at_ms: Option<i64>,
}

impl CircuitBreaker {
    pub fn new(
        failure_threshold: u32,
        cooldown_ms: i64,
        half_open_successes: u32,
    ) -> Result<Self, String> {
        if failure_threshold == 0 {
            return Err("failure_threshold must be greater than zero".to_string());
        }
        if cooldown_ms <= 0 {
            return Err("cooldown_ms must be greater than zero".to_string());
        }
        if half_open_successes == 0 {
            return Err("half_open_successes must be greater than zero".to_string());
        }
        Ok(Self {
            failure_threshold,
            cooldown_ms,
            half_open_successes,
            failures: 0,
            successes_in_half_open: 0,
            state: BreakerState::Closed,
            opened_at_ms: None,
        })
    }

    fn cooled_down(&self, now_ms: i64) -> bool {
        match self.opened_at_ms {
            Some(opened) => now_ms.saturating_sub(opened) >= self.cooldown_ms,
            None => false,
        }
    }

    /// Ask for permission before doing the protected work.
    pub fn allow(&mut self, now_ms: i64) -> bool {
        match self.state {
            BreakerState::Closed | BreakerState::HalfOpen => true,
            BreakerState::Open => {
                if self.cooled_down(now_ms) {
                    self.state = BreakerState::HalfOpen;
                    self.successes_in_half_open = 0;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Report the outcome of the protected work.
    pub fn record(&mut self, success: bool, now_ms: i64) {
        match self.state {
            BreakerState::Closed => {
                if success {
                    self.failures = 0;
                } else {
                    self.failures += 1;
                    if self.failures >= self.failure_threshold {
                        self.state = BreakerState::Open;
                        self.opened_at_ms = Some(now_ms);
                    }
                }
            }
            BreakerState::HalfOpen => {
                if success {
                    self.successes_in_half_open += 1;
                    if self.successes_in_half_open >= self.half_open_successes {
                        self.state = BreakerState::Closed;
                        self.failures = 0;
                        self.opened_at_ms = None;
                    }
                } else {
                    self.state = BreakerState::Open;
                    self.opened_at_ms = Some(now_ms);
                    self.successes_in_half_open = 0;
                }
            }
            BreakerState::Open => {
                // Work is not supposed to run while open; a late report is ignored.
            }
        }
    }

    pub fn status(&self, now_ms: i64) -> BreakerStatus {
        let allowed = match self.state {
            BreakerState::Closed | BreakerState::HalfOpen => true,
            BreakerState::Open => self.cooled_down(now_ms),
        };
        BreakerStatus {
            state: self.state,
            failures: self.failures,
            opened_at_ms: self.opened_at_ms,
            allowed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateStatus {
    pub allowed: bool,
    pub tokens: f64,
    pub capacity: f64,
}

pub struct RateLimiter {
    capacity: f64,
    refill_per_ms: f64,
    tokens: f64,
    last_ms: i64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_second: f64, now_ms: i64) -> Result<Self, String> {
        if !capacity.is_finite() || capacity <= 0.0 {
            return Err("capacity must be finite and greater than zero".to_string());
        }
        if !refill_per_second.is_finite() || refill_per_second < 0.0 {
            return Err("refill_per_second must be finite and not negative".to_string());
        }
        Ok(Self {
            capacity,
            refill_per_ms: refill_per_second / 1000.0,
            tokens: capacity,
            last_ms: now_ms,
        })
    }

    fn refill(&mut self, now_ms: i64) -> Result<(), String> {
        if now_ms < self.last_ms {
            return Err("clock moved backwards; refusing to refill".to_string());
        }
        let elapsed = (now_ms - self.last_ms) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.last_ms = now_ms;
        Ok(())
    }

    pub fn try_acquire(&mut self, cost: f64, now_ms: i64) -> Result<RateStatus, String> {
        if !cost.is_finite() || cost <= 0.0 {
            return Err("cost must be finite and greater than zero".to_string());
        }
        if cost > self.capacity {
            return Err("cost exceeds capacity, so it can never succeed".to_string());
        }
        self.refill(now_ms)?;
        let allowed = self.tokens >= cost;
        if allowed {
            self.tokens -= cost;
        }
        Ok(RateStatus {
            allowed,
            tokens: self.tokens,
            capacity: self.capacity,
        })
    }

    pub fn status(&self) -> RateStatus {
        RateStatus {
            allowed: self.tokens > 0.0,
            tokens: self.tokens,
            capacity: self.capacity,
        }
    }
}
