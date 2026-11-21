//! One neuron, with the arithmetic written out.
//!
//! A neuron is a dot product plus a bias, passed through a sigmoid, and a
//! gradient step that nudges each weight by `-rate * error * input`. Nothing
//! here is hidden: every function is the formula.

use std::time::Instant;

pub fn dot(inputs: &[f64], weights: &[f64]) -> Result<f64, String> {
    if inputs.len() != weights.len() {
        return Err(format!("length mismatch: {} inputs, {} weights", inputs.len(), weights.len()));
    }
    if inputs.is_empty() {
        return Err("the vectors are empty".into());
    }
    Ok(inputs.iter().zip(weights).map(|(x, w)| x * w).sum())
}

pub fn sigmoid(value: f64) -> f64 {
    1.0 / (1.0 + (-value.clamp(-60.0, 60.0)).exp())
}

pub fn forward(inputs: &[f64], weights: &[f64], bias: f64) -> Result<f64, String> {
    Ok(sigmoid(dot(inputs, weights)? + bias))
}

pub fn train_step(
    inputs: &[f64],
    weights: &[f64],
    bias: f64,
    target: f64,
    rate: f64,
) -> Result<(Vec<f64>, f64, f64, f64), String> {
    if !(0.0..=1.0).contains(&target) {
        return Err("the target must be between 0 and 1".into());
    }
    if rate <= 0.0 {
        return Err("the rate must be positive".into());
    }
    let prediction = forward(inputs, weights, bias)?;
    let error = prediction - target;
    let loss = -target * prediction.ln().max(-60.0) - (1.0 - target) * (1.0 - prediction).ln().max(-60.0);
    let updated: Vec<f64> = inputs
        .iter()
        .zip(weights)
        .map(|(x, w)| w - rate * error * x)
        .collect();
    Ok((updated, bias - rate * error, prediction, loss))
}

pub fn parse_list(text: &str) -> Result<Vec<f64>, String> {
    let mut values = Vec::new();
    for piece in text.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        values.push(piece.parse::<f64>().map_err(|error| format!("bad number {piece}: {error}"))?);
    }
    if values.is_empty() {
        return Err("the list is empty".into());
    }
    Ok(values)
}

pub fn bench(dimension: usize, repeats: usize) -> Result<(f64, f64, f64), String> {
    if dimension == 0 || repeats == 0 || dimension > 5_000_000 {
        return Err("dimension and repeats must be positive and bounded".into());
    }
    let inputs: Vec<f64> = (0..dimension).map(|index| ((index % 97) as f64) / 97.0).collect();
    let weights: Vec<f64> = (0..dimension).map(|index| ((index % 89) as f64) / 89.0 - 0.5).collect();
    let started = Instant::now();
    let mut total = 0.0;
    for _ in 0..repeats {
        total += dot(&inputs, &weights)?;
    }
    let elapsed = started.elapsed().as_secs_f64();
    Ok((elapsed * 1000.0 / repeats as f64, total, elapsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_is_the_sum_of_products() {
        assert_eq!(dot(&[10.0, 20.0, 30.0], &[0.5, -1.0, 2.0]).unwrap(), 45.0);
        assert_eq!(dot(&[1.0], &[0.0]).unwrap(), 0.0);
        assert!(dot(&[1.0, 2.0], &[1.0]).is_err());
        assert!(dot(&[], &[]).is_err());
    }

    #[test]
    fn sigmoid_is_bounded_and_centred() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-12);
        assert!(sigmoid(50.0) > 0.999);
        assert!(sigmoid(-50.0) < 0.001);
        assert!((sigmoid(60.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn training_moves_towards_the_target() {
        let inputs = [1.0, -2.0, 0.5];
        let mut weights = vec![0.1, -0.2, 0.3];
        let mut bias = 0.0;
        let before = forward(&inputs, &weights, bias).unwrap();
        for _ in 0..200 {
            let (next, next_bias, _, _) = train_step(&inputs, &weights, bias, 1.0, 0.5).unwrap();
            weights = next;
            bias = next_bias;
        }
        let after = forward(&inputs, &weights, bias).unwrap();
        assert!(after > before);
        assert!(after > 0.95);
    }

    #[test]
    fn bad_training_inputs_are_refused() {
        assert!(train_step(&[1.0], &[0.0], 0.0, 2.0, 0.1).is_err());
        assert!(train_step(&[1.0], &[0.0], 0.0, 0.5, 0.0).is_err());
        assert!(train_step(&[1.0], &[0.0], 0.0, 0.5, 0.1).is_ok());
    }

    #[test]
    fn bench_reports_a_positive_rate() {
        let (ms, total, _) = bench(10_000, 3).unwrap();
        assert!(ms > 0.0);
        assert!(total.abs() > 0.0);
        assert!(bench(0, 1).is_err());
    }
}
