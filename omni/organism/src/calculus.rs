//! Calculus: gradients, optimisers, and numerical integration.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Quadratic {
    pub target: f64,
    pub weight: f64,
}

impl Quadratic {
    pub fn new(target: f64, weight: f64) -> Result<Self, String> {
        if !target.is_finite() || !weight.is_finite() {
            return Err("quadratic parameters must be finite".into());
        }
        if weight <= 0.0 {
            return Err("weight must be positive".into());
        }
        Ok(Self { target, weight })
    }

    pub fn loss(&self, x: f64) -> f64 {
        self.weight * (x - self.target).powi(2)
    }

    pub fn gradient(&self, x: f64) -> f64 {
        2.0 * self.weight * (x - self.target)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Trajectory {
    pub xs: Vec<f64>,
    pub losses: Vec<f64>,
}

/// Plain gradient descent. The step size must satisfy `lr < 1 / weight`,
/// otherwise the quadratic diverges and the caller gets an error instead.
pub fn descend(
    objective: &Quadratic,
    start: f64,
    lr: f64,
    iterations: usize,
) -> Result<Trajectory, String> {
    if !start.is_finite() {
        return Err("start must be finite".into());
    }
    if !(lr.is_finite() && lr > 0.0 && lr < 1.0 / objective.weight) {
        return Err(format!(
            "learning rate must be in (0, {})",
            1.0 / objective.weight
        ));
    }
    let mut x = start;
    let mut xs = Vec::with_capacity(iterations + 1);
    let mut losses = Vec::with_capacity(iterations + 1);
    xs.push(x);
    losses.push(objective.loss(x));
    for _ in 0..iterations {
        x -= lr * objective.gradient(x);
        xs.push(x);
        losses.push(objective.loss(x));
    }
    Ok(Trajectory { xs, losses })
}

/// Adam optimiser state for a single scalar parameter.
#[derive(Debug, Clone)]
pub struct Adam {
    m: f64,
    v: f64,
    beta1: f64,
    beta2: f64,
    eps: f64,
    steps: u64,
}

impl Default for Adam {
    fn default() -> Self {
        Self::new()
    }
}

impl Adam {
    pub fn new() -> Self {
        Self {
            m: 0.0,
            v: 0.0,
            beta1: 0.9,
            beta2: 0.999,
            eps: 1e-8,
            steps: 0,
        }
    }

    pub fn step(&mut self, x: f64, grad: f64, lr: f64) -> f64 {
        self.steps += 1;
        self.m = self.beta1 * self.m + (1.0 - self.beta1) * grad;
        self.v = self.beta2 * self.v + (1.0 - self.beta2) * grad * grad;
        let m_hat = self.m / (1.0 - self.beta1.powi(self.steps as i32));
        let v_hat = self.v / (1.0 - self.beta2.powi(self.steps as i32));
        x - lr * m_hat / (v_hat.sqrt() + self.eps)
    }
}

/// Central-difference derivative, used to check the analytic gradient.
pub fn numerical_gradient<F: Fn(f64) -> f64>(f: F, x: f64, h: f64) -> Result<f64, String> {
    if !(h.is_finite() && h > 0.0) {
        return Err("h must be positive and finite".into());
    }
    Ok((f(x + h) - f(x - h)) / (2.0 * h))
}

/// Composite Simpson's rule. `n` must be a positive even number.
pub fn simpson<F: Fn(f64) -> f64>(f: F, a: f64, b: f64, n: usize) -> Result<f64, String> {
    if !a.is_finite() || !b.is_finite() {
        return Err("bounds must be finite".into());
    }
    if b <= a {
        return Err("b must be greater than a".into());
    }
    if n == 0 || !n.is_multiple_of(2) {
        return Err("n must be a positive even number".into());
    }
    let h = (b - a) / n as f64;
    let mut sum = f(a) + f(b);
    for i in 1..n {
        let x = a + i as f64 * h;
        sum += if i % 2 == 0 { 2.0 * f(x) } else { 4.0 * f(x) };
    }
    Ok(sum * h / 3.0)
}
