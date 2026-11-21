//! Homeostatic control: setpoints, deadbands, priority, and load metering.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Homeostat {
    pub name: String,
    pub target: f64,
    pub current: f64,
    pub tolerance: f64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub name: String,
    /// Positive means a deficit (need more), negative means an excess.
    pub error: f64,
    pub urgency: f64,
    pub satisfied: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Load {
    pub used: f64,
    pub fraction: f64,
    pub overheated: bool,
    pub throttled: bool,
}

#[derive(Debug, Clone)]
pub struct ControlBoard {
    homes: Vec<Homeostat>,
}

impl ControlBoard {
    pub fn new(homes: Vec<Homeostat>) -> Result<Self, String> {
        if homes.is_empty() {
            return Err("at least one homeostat is required".into());
        }
        if homes.len() > 64 {
            return Err("at most 64 homeostats are supported".into());
        }
        let mut seen = std::collections::HashSet::new();
        for home in &homes {
            if !(home.target.is_finite() && home.current.is_finite()) {
                return Err(format!("homeostat {} has a non-finite value", home.name));
            }
            if !(home.tolerance.is_finite() && home.tolerance > 0.0) {
                return Err(format!("homeostat {} needs a positive tolerance", home.name));
            }
            if !(home.weight.is_finite() && home.weight > 0.0) {
                return Err(format!("homeostat {} needs a positive weight", home.name));
            }
            if !seen.insert(home.name.clone()) {
                return Err(format!("duplicate homeostat: {}", home.name));
            }
        }
        Ok(Self { homes })
    }

    pub fn names(&self) -> Vec<String> {
        self.homes.iter().map(|home| home.name.clone()).collect()
    }

    pub fn set(&mut self, name: &str, value: f64) -> Result<(), String> {
        if !value.is_finite() {
            return Err("value must be finite".into());
        }
        let home = self
            .homes
            .iter_mut()
            .find(|home| home.name == name)
            .ok_or_else(|| format!("unknown homeostat: {name}"))?;
        home.current = value;
        Ok(())
    }

    pub fn adjust(&mut self, name: &str, delta: f64) -> Result<f64, String> {
        if !delta.is_finite() {
            return Err("delta must be finite".into());
        }
        let home = self
            .homes
            .iter_mut()
            .find(|home| home.name == name)
            .ok_or_else(|| format!("unknown homeostat: {name}"))?;
        home.current += delta;
        Ok(home.current)
    }

    pub fn signals(&self) -> Vec<Signal> {
        self.homes
            .iter()
            .map(|home| {
                let error = (home.target - home.current) / home.tolerance;
                Signal {
                    name: home.name.clone(),
                    error,
                    urgency: (error.abs() * home.weight).clamp(0.0, 1.0),
                    satisfied: error.abs() <= 1.0,
                }
            })
            .collect()
    }

    /// The unsatisfied signal with the highest urgency, if any.
    pub fn dominant(&self) -> Option<Signal> {
        self.signals()
            .into_iter()
            .filter(|signal| !signal.satisfied)
            .max_by(|a, b| a.urgency.total_cmp(&b.urgency))
    }

    /// Proportional correction with a step cap. Returns the new value.
    pub fn step(&mut self, name: &str, gain: f64, max_step: f64) -> Result<f64, String> {
        if !(gain.is_finite() && gain > 0.0 && gain <= 1.0) {
            return Err("gain must be in (0, 1]".into());
        }
        if !(max_step.is_finite() && max_step > 0.0) {
            return Err("max_step must be positive".into());
        }
        let home = self
            .homes
            .iter_mut()
            .find(|home| home.name == name)
            .ok_or_else(|| format!("unknown homeostat: {name}"))?;
        let delta = ((home.target - home.current) * gain).clamp(-max_step, max_step);
        home.current += delta;
        Ok(home.current)
    }
}

#[derive(Debug, Clone)]
pub struct LoadMeter {
    capacity: f64,
    window_ms: i64,
    used: f64,
    window_start: i64,
}

impl LoadMeter {
    pub fn new(capacity: f64, window_ms: i64) -> Result<Self, String> {
        if !(capacity.is_finite() && capacity > 0.0) {
            return Err("capacity must be positive".into());
        }
        if window_ms <= 0 {
            return Err("window_ms must be positive".into());
        }
        Ok(Self {
            capacity,
            window_ms,
            used: 0.0,
            window_start: 0,
        })
    }

    pub fn charge(&mut self, cost: f64, now_ms: i64) -> Result<Load, String> {
        if !(cost.is_finite() && cost >= 0.0) {
            return Err("cost must be finite and non-negative".into());
        }
        if now_ms - self.window_start >= self.window_ms {
            self.window_start = now_ms;
            self.used = 0.0;
        }
        self.used += cost;
        let fraction = self.used / self.capacity;
        Ok(Load {
            used: self.used,
            fraction,
            overheated: fraction >= 1.0,
            throttled: fraction >= 0.8,
        })
    }
}
