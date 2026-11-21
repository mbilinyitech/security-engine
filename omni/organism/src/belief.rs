//! Beliefs: Beta posteriors, entropy, expected utility, and a UCB1 bandit.

use serde::{Deserialize, Serialize};

/// Lanczos approximation of ln Gamma(x) for x > 0.
pub fn ln_gamma(x: f64) -> Result<f64, String> {
    if !(x.is_finite() && x > 0.0) {
        return Err("ln_gamma needs a positive finite argument".into());
    }
    const COEFFICIENTS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Reflection: Gamma(x)Gamma(1-x) = pi / sin(pi x)
        let reflected = std::f64::consts::PI / (std::f64::consts::PI * x).sin();
        return Ok((std::f64::consts::PI / reflected).ln() - ln_gamma(1.0 - x)?);
    }
    let shifted = x - 1.0;
    let mut series = COEFFICIENTS[0];
    for (index, coefficient) in COEFFICIENTS.iter().enumerate().skip(1) {
        series += coefficient / (shifted + index as f64);
    }
    let t = shifted + 7.5;
    Ok(0.5 * (2.0 * std::f64::consts::PI).ln() + (shifted + 0.5) * t.ln() - t + series.ln())
}

/// Digamma via recurrence plus an asymptotic series.
pub fn digamma(x: f64) -> Result<f64, String> {
    if !(x.is_finite() && x > 0.0) {
        return Err("digamma needs a positive finite argument".into());
    }
    let mut value = x;
    let mut shift = 0.0;
    while value < 6.0 {
        shift -= 1.0 / value;
        value += 1.0;
    }
    let inverse = 1.0 / value;
    let inverse2 = inverse * inverse;
    let series = value.ln()
        - 0.5 * inverse
        - inverse2 * (1.0 / 12.0 - inverse2 * (1.0 / 120.0 - inverse2 / 252.0));
    Ok(series + shift)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BetaBelief {
    pub alpha: f64,
    pub beta: f64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct BeliefSummary {
    pub alpha: f64,
    pub beta: f64,
    pub mean: f64,
    pub variance: f64,
    pub entropy: f64,
    pub observations: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    pub utility_success: f64,
    pub utility_failure: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Arm {
    pub name: String,
    pub pulls: u32,
    pub reward: f64,
}

impl BetaBelief {
    pub fn new(alpha: f64, beta: f64) -> Result<Self, String> {
        if !(alpha.is_finite() && alpha > 0.0) || !(beta.is_finite() && beta > 0.0) {
            return Err("alpha and beta must be positive and finite".into());
        }
        Ok(Self { alpha, beta })
    }

    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    pub fn variance(&self) -> f64 {
        let total = self.alpha + self.beta;
        (self.alpha * self.beta) / (total * total * (total + 1.0))
    }

    /// Differential entropy of the Beta distribution.
    pub fn entropy(&self) -> Result<f64, String> {
        let (a, b) = (self.alpha, self.beta);
        let ln_beta = ln_gamma(a)? + ln_gamma(b)? - ln_gamma(a + b)?;
        Ok(ln_beta - (a - 1.0) * digamma(a)? - (b - 1.0) * digamma(b)?
            + (a + b - 2.0) * digamma(a + b)?)
    }

    pub fn observe(&mut self, success: bool) {
        if success {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
    }

    pub fn observe_batch(&mut self, successes: u32, failures: u32) {
        self.alpha += successes as f64;
        self.beta += failures as f64;
    }

    /// Log marginal likelihood of a batch under this prior.
    pub fn log_likelihood(&self, successes: u32, failures: u32) -> Result<f64, String> {
        let a = self.alpha + successes as f64;
        let b = self.beta + failures as f64;
        Ok(ln_gamma(a)? + ln_gamma(b)? - ln_gamma(a + b)?
            - (ln_gamma(self.alpha)? + ln_gamma(self.beta)? - ln_gamma(self.alpha + self.beta)?))
    }

    pub fn summary(&self) -> Result<BeliefSummary, String> {
        Ok(BeliefSummary {
            alpha: self.alpha,
            beta: self.beta,
            mean: self.mean(),
            variance: self.variance(),
            entropy: self.entropy()?,
            observations: self.alpha + self.beta - 2.0,
        })
    }
}

/// Expected utility of each action under the belief; returns the best one.
pub fn decide(
    belief: &BetaBelief,
    actions: &[Action],
) -> Result<(String, Vec<(String, f64)>), String> {
    if actions.is_empty() {
        return Err("at least one action is required".into());
    }
    if actions.len() > 1_000 {
        return Err("at most 1000 actions are supported".into());
    }
    let p = belief.mean();
    let mut scored = Vec::with_capacity(actions.len());
    for action in actions {
        if !(action.utility_success.is_finite() && action.utility_failure.is_finite()) {
            return Err(format!("action {} has a non-finite utility", action.name));
        }
        let expected = p * action.utility_success + (1.0 - p) * action.utility_failure;
        scored.push((action.name.clone(), expected));
    }
    let mut best = scored[0].clone();
    for candidate in scored.iter().skip(1) {
        if candidate.1 > best.1 {
            best = candidate.clone();
        }
    }
    Ok((best.0, scored))
}

#[derive(Debug, Clone, Default)]
pub struct Bandit {
    arms: Vec<Arm>,
}

impl Bandit {
    pub fn new(names: &[String]) -> Result<Self, String> {
        if names.is_empty() || names.len() > 10_000 {
            return Err("bandit needs between 1 and 10000 arms".into());
        }
        Ok(Self {
            arms: names
                .iter()
                .map(|name| Arm {
                    name: name.clone(),
                    pulls: 0,
                    reward: 0.0,
                })
                .collect(),
        })
    }

    pub fn arms(&self) -> &[Arm] {
        &self.arms
    }

    /// UCB1: unvisited arms first, then mean reward plus an exploration bonus.
    pub fn select(&self) -> Result<usize, String> {
        if self.arms.is_empty() {
            return Err("bandit has no arms".into());
        }
        let total: u64 = self.arms.iter().map(|arm| arm.pulls as u64).sum();
        let mut best = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (index, arm) in self.arms.iter().enumerate() {
            let score = if arm.pulls == 0 {
                f64::INFINITY
            } else {
                arm.reward / arm.pulls as f64
                    + (2.0 * (total.max(1) as f64).ln() / arm.pulls as f64).sqrt()
            };
            if score > best_score {
                best_score = score;
                best = index;
            }
        }
        Ok(best)
    }

    pub fn update(&mut self, index: usize, reward: f64) -> Result<(), String> {
        if !(reward.is_finite() && (0.0..=1.0).contains(&reward)) {
            return Err("reward must be in [0, 1]".into());
        }
        let arm = self
            .arms
            .get_mut(index)
            .ok_or_else(|| format!("unknown arm index {index}"))?;
        arm.pulls = arm.pulls.saturating_add(1);
        arm.reward += reward;
        Ok(())
    }
}
