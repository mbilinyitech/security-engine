//! Compute budget meter.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyMeter {
    capacity: f64,
    level: f64,
    starvation_threshold: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TickReport {
    pub level: f64,
    pub fraction: f64,
    pub starving: bool,
    pub dead: bool,
}

fn finite(value: f64, name: &str) -> Result<f64, String> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("{name} must be finite"))
    }
}

impl EnergyMeter {
    pub fn new(capacity: f64, starvation_threshold: f64) -> Result<Self, String> {
        let capacity = finite(capacity, "capacity")?;
        let starvation_threshold = finite(starvation_threshold, "starvation_threshold")?;
        if capacity <= 0.0 {
            return Err("capacity must be positive".into());
        }
        if !(0.0..1.0).contains(&starvation_threshold) {
            return Err("starvation_threshold must be in [0, 1)".into());
        }
        Ok(Self {
            capacity,
            level: capacity,
            starvation_threshold,
        })
    }

    pub fn level(&self) -> f64 {
        self.level
    }

    pub fn capacity(&self) -> f64 {
        self.capacity
    }

    pub fn fraction(&self) -> f64 {
        self.level / self.capacity
    }

    pub fn is_starving(&self) -> bool {
        self.fraction() < self.starvation_threshold
    }

    pub fn is_dead(&self) -> bool {
        self.level <= 0.0
    }

    /// Spend budget, never below zero. Returns what was actually spent.
    pub fn consume(&mut self, amount: f64) -> Result<f64, String> {
        let amount = finite(amount, "amount")?;
        if amount < 0.0 {
            return Err("amount must be non-negative".into());
        }
        let taken = amount.min(self.level);
        self.level -= taken;
        Ok(taken)
    }

    /// Add budget, never above capacity. Returns what was actually stored.
    pub fn recharge(&mut self, amount: f64) -> Result<f64, String> {
        let amount = finite(amount, "amount")?;
        if amount < 0.0 {
            return Err("amount must be non-negative".into());
        }
        let before = self.level;
        self.level = (self.level + amount).min(self.capacity);
        Ok(self.level - before)
    }

    pub fn tick(&mut self, cost: f64, recharge: f64) -> Result<TickReport, String> {
        self.consume(cost)?;
        self.recharge(recharge)?;
        Ok(TickReport {
            level: self.level,
            fraction: self.fraction(),
            starving: self.is_starving(),
            dead: self.is_dead(),
        })
    }
}
