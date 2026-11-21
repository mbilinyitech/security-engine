//! Monte Carlo Tree Search with UCB1 and a deterministic RNG.

use serde::Serialize;

/// xorshift64* — small, fast, reproducible. Not cryptographic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
                | 1,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(2685821657736338717)
    }

    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn next_range(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// A finite, deterministic game that MCTS can search.
pub trait Game: Clone {
    fn legal_actions(&self) -> Vec<u32>;
    fn apply(&self, action: u32) -> Self;
    fn is_terminal(&self) -> bool;
    /// Reward from the perspective of the player to move.
    fn reward(&self) -> f64;
    /// Cheap progress signal used to bias rollouts. Defaults to no signal.
    fn heuristic(&self) -> f64 {
        0.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChildStat {
    pub action: u32,
    pub visits: u32,
    pub mean_value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MctsReport {
    pub best_action: u32,
    pub visits: u32,
    pub mean_value: f64,
    pub children: Vec<ChildStat>,
}

struct Node {
    visits: u32,
    value: f64,
    children: Vec<(u32, usize)>,
    parent: Option<usize>,
}

fn ucb(node: &Node, parent_visits: u32) -> f64 {
    if node.visits == 0 {
        return f64::INFINITY;
    }
    let exploitation = node.value / node.visits as f64;
    let exploration =
        (2.0 * (parent_visits.max(1) as f64).ln() / node.visits as f64).sqrt();
    exploitation + 1.41 * exploration
}

pub fn search<G: Game>(
    root: &G,
    iterations: u32,
    horizon: usize,
    seed: u64,
) -> Result<MctsReport, String> {
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    if horizon == 0 {
        return Err("horizon must be positive".into());
    }
    if root.legal_actions().is_empty() {
        return Err("root state has no legal actions".into());
    }
    let mut rng = Rng::new(seed);
    let mut tree = vec![Node {
        visits: 0,
        value: 0.0,
        children: Vec::new(),
        parent: None,
    }];

    for _ in 0..iterations {
        let mut node = 0usize;
        let mut state = root.clone();

        // Selection
        while !state.is_terminal() && !tree[node].children.is_empty() {
            let parent_visits = tree[node].visits;
            let mut best = 0usize;
            let mut best_score = f64::NEG_INFINITY;
            for (index, (_, child)) in tree[node].children.iter().enumerate() {
                let score = ucb(&tree[*child], parent_visits);
                if score > best_score {
                    best_score = score;
                    best = index;
                }
            }
            let (action, child) = tree[node].children[best];
            state = state.apply(action);
            node = child;
        }

        // Expansion
        if !state.is_terminal() {
            for action in state.legal_actions() {
                let child = tree.len();
                tree.push(Node {
                    visits: 0,
                    value: 0.0,
                    children: Vec::new(),
                    parent: Some(node),
                });
                tree[node].children.push((action, child));
            }
            let (action, child) = tree[node].children[0];
            state = state.apply(action);
            node = child;
        }

        // Simulation
        let mut sim = state;
        let mut depth = 0usize;
        while !sim.is_terminal() && depth < horizon {
            let actions = sim.legal_actions();
            if actions.is_empty() {
                break;
            }
            // Guided rollouts: mostly follow the progress signal, sometimes
            // explore. Pure uniform rollouts cannot reach a distant goal
            // within a short horizon, which makes the tree blind.
            let action = if rng.next_f64() < 0.8 {
                let mut best_action = actions[0];
                let mut best_score = f64::NEG_INFINITY;
                for candidate in &actions {
                    let score = sim.apply(*candidate).heuristic();
                    if score > best_score {
                        best_score = score;
                        best_action = *candidate;
                    }
                }
                best_action
            } else {
                actions[rng.next_range(actions.len())]
            };
            sim = sim.apply(action);
            depth += 1;
        }
        let value = if sim.is_terminal() { sim.reward() } else { 0.0 };

        // Backpropagation
        let mut cursor = Some(node);
        while let Some(current) = cursor {
            tree[current].visits += 1;
            tree[current].value += value;
            cursor = tree[current].parent;
        }
    }

    let mut stats: Vec<ChildStat> = tree[0]
        .children
        .iter()
        .map(|(action, index)| {
            let node = &tree[*index];
            ChildStat {
                action: *action,
                visits: node.visits,
                mean_value: if node.visits == 0 {
                    0.0
                } else {
                    node.value / node.visits as f64
                },
            }
        })
        .collect();
    stats.sort_by(|a, b| {
        b.visits
            .cmp(&a.visits)
            .then(b.mean_value.total_cmp(&a.mean_value))
    });
    let best = stats[0].clone();
    Ok(MctsReport {
        best_action: best.action,
        visits: best.visits,
        mean_value: best.mean_value,
        children: stats,
    })
}

/// A one-dimensional world: action 1 moves right, action 0 moves left.
/// Reaching the right edge is terminal with reward 1.
#[derive(Debug, Clone, Copy)]
pub struct LineGame {
    position: usize,
    length: usize,
}

impl LineGame {
    pub fn new(length: usize) -> Result<Self, String> {
        if length < 2 {
            return Err("length must be at least 2".into());
        }
        if length > 1_000_000 {
            return Err("length above 1000000 is refused".into());
        }
        Ok(Self {
            position: 0,
            length,
        })
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

impl Game for LineGame {
    fn legal_actions(&self) -> Vec<u32> {
        if self.is_terminal() {
            Vec::new()
        } else {
            vec![0, 1]
        }
    }

    fn apply(&self, action: u32) -> Self {
        let mut next = *self;
        if action == 1 {
            next.position = (next.position + 1).min(next.length - 1);
        } else {
            next.position = next.position.saturating_sub(1);
        }
        next
    }

    fn is_terminal(&self) -> bool {
        self.position + 1 >= self.length
    }

    fn reward(&self) -> f64 {
        if self.is_terminal() {
            1.0
        } else {
            0.0
        }
    }

    fn heuristic(&self) -> f64 {
        self.position as f64 / (self.length - 1) as f64
    }
}
