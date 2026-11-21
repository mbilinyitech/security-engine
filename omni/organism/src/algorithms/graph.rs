//! Memory graph with PageRank.

use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct MemoryGraph {
    labels: Vec<String>,
    edges: Vec<Vec<(usize, f64)>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RankedNode {
    pub node: usize,
    pub label: String,
    pub score: f64,
}

impl MemoryGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, label: impl Into<String>) -> usize {
        self.labels.push(label.into());
        self.edges.push(Vec::new());
        self.labels.len() - 1
    }

    pub fn node_count(&self) -> usize {
        self.labels.len()
    }

    pub fn add_edge(&mut self, from: usize, to: usize, weight: f64) -> Result<(), String> {
        if from >= self.node_count() || to >= self.node_count() {
            return Err("edge endpoint is out of range".into());
        }
        if !(weight.is_finite() && weight > 0.0) {
            return Err("edge weight must be finite and positive".into());
        }
        self.edges[from].push((to, weight));
        Ok(())
    }

    /// Power iteration with dangling-node redistribution. Scores sum to 1.
    pub fn pagerank(
        &self,
        damping: f64,
        iterations: usize,
        tolerance: f64,
    ) -> Result<Vec<f64>, String> {
        let n = self.node_count();
        if n == 0 {
            return Err("graph has no nodes".into());
        }
        if !(damping.is_finite() && damping > 0.0 && damping < 1.0) {
            return Err("damping must be in (0, 1)".into());
        }
        if iterations == 0 {
            return Err("iterations must be positive".into());
        }
        if !(tolerance.is_finite() && tolerance > 0.0) {
            return Err("tolerance must be positive and finite".into());
        }

        let mut scores = vec![1.0 / n as f64; n];
        let out_weight: Vec<f64> = self
            .edges
            .iter()
            .map(|edges| edges.iter().map(|(_, weight)| weight).sum())
            .collect();

        for _ in 0..iterations {
            let mut next = vec![(1.0 - damping) / n as f64; n];
            let mut dangling = 0.0;
            for from in 0..n {
                if out_weight[from] == 0.0 {
                    dangling += scores[from];
                    continue;
                }
                for (to, weight) in &self.edges[from] {
                    next[*to] += damping * scores[from] * (weight / out_weight[from]);
                }
            }
            let share = damping * dangling / n as f64;
            for value in next.iter_mut() {
                *value += share;
            }
            let delta: f64 = next
                .iter()
                .zip(&scores)
                .map(|(new, old)| (new - old).abs())
                .sum();
            scores = next;
            if delta < tolerance {
                break;
            }
        }
        Ok(scores)
    }

    pub fn ranked(&self, scores: &[f64], top_k: usize) -> Vec<RankedNode> {
        let mut ranked: Vec<RankedNode> = scores
            .iter()
            .enumerate()
            .map(|(node, score)| RankedNode {
                node,
                label: self.labels[node].clone(),
                score: *score,
            })
            .collect();
        ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.node.cmp(&b.node)));
        ranked.truncate(top_k);
        ranked
    }
}
