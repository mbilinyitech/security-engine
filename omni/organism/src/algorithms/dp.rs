//! 0/1 knapsack by dynamic programming, with reconstruction.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct KnapsackResult {
    pub best_value: u64,
    pub total_weight: u64,
    pub items: Vec<usize>,
}

pub fn knapsack(weights: &[u64], values: &[u64], capacity: u64) -> Result<KnapsackResult, String> {
    if weights.len() != values.len() {
        return Err("weights and values must have the same length".into());
    }
    if weights.len() > 5_000 {
        return Err("more than 5000 items is refused".into());
    }
    if capacity > 200_000 {
        return Err("capacity above 200000 is refused".into());
    }
    let cap = capacity as usize;
    let mut best = vec![0u64; cap + 1];
    let words = cap / 64 + 1;
    let mut taken = vec![vec![0u64; words]; weights.len()];

    for (index, (&weight, &value)) in weights.iter().zip(values).enumerate() {
        if weight == 0 || weight > capacity {
            continue;
        }
        let weight = weight as usize;
        for current in (weight..=cap).rev() {
            let candidate = best[current - weight] + value;
            if candidate > best[current] {
                best[current] = candidate;
                taken[index][current / 64] |= 1 << (current % 64);
            }
        }
    }

    let mut items = Vec::new();
    let mut current = cap;
    for index in (0..weights.len()).rev() {
        if taken[index][current / 64] & (1 << (current % 64)) != 0 {
            items.push(index);
            current -= weights[index] as usize;
        }
    }
    items.reverse();
    let total_weight: u64 = items.iter().map(|&index| weights[index]).sum();
    Ok(KnapsackResult {
        best_value: best[cap],
        total_weight,
        items,
    })
}
