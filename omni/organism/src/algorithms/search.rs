//! Graph search: A* and Dijkstra over an explicit adjacency list.

use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub to: usize,
    pub cost: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SearchResult {
    pub path: Vec<usize>,
    pub cost: f64,
    pub expanded: usize,
}

#[derive(Debug, Clone, Copy)]
struct QueueItem {
    estimate: f64,
    cost: f64,
    node: usize,
}

impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.estimate == other.estimate && self.node == other.node
    }
}

impl Eq for QueueItem {}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so BinaryHeap (a max-heap) pops the smallest estimate first.
        other
            .estimate
            .total_cmp(&self.estimate)
            .then_with(|| other.node.cmp(&self.node))
    }
}

fn validate(nodes: usize, start: usize, goal: usize) -> Result<(), String> {
    if nodes == 0 {
        return Err("graph must have at least one node".into());
    }
    if nodes > 100_000 {
        return Err("graph larger than 100000 nodes is refused".into());
    }
    if start >= nodes || goal >= nodes {
        return Err("start and goal must be valid node indices".into());
    }
    Ok(())
}

/// A* with an admissible heuristic. Returns the optimal path when one exists.
pub fn astar<F, H>(
    nodes: usize,
    start: usize,
    goal: usize,
    neighbors: F,
    heuristic: H,
) -> Result<Option<SearchResult>, String>
where
    F: Fn(usize) -> Vec<Edge>,
    H: Fn(usize) -> f64,
{
    validate(nodes, start, goal)?;
    let mut best_cost = vec![f64::INFINITY; nodes];
    let mut came_from: Vec<Option<usize>> = vec![None; nodes];
    let mut queue = BinaryHeap::new();
    let mut expanded = 0usize;

    best_cost[start] = 0.0;
    queue.push(QueueItem {
        estimate: heuristic(start),
        cost: 0.0,
        node: start,
    });

    while let Some(item) = queue.pop() {
        if item.node == goal {
            let mut path = vec![goal];
            let mut cursor = goal;
            while let Some(previous) = came_from[cursor] {
                path.push(previous);
                cursor = previous;
            }
            path.reverse();
            return Ok(Some(SearchResult {
                path,
                cost: item.cost,
                expanded,
            }));
        }
        if item.cost > best_cost[item.node] {
            continue;
        }
        expanded += 1;
        for edge in neighbors(item.node) {
            if edge.to >= nodes {
                return Err(format!("edge points at unknown node {}", edge.to));
            }
            if !(edge.cost.is_finite() && edge.cost >= 0.0) {
                return Err("edge costs must be finite and non-negative".into());
            }
            let candidate = item.cost + edge.cost;
            if candidate < best_cost[edge.to] {
                best_cost[edge.to] = candidate;
                came_from[edge.to] = Some(item.node);
                let estimate = candidate + heuristic(edge.to);
                if !estimate.is_finite() {
                    return Err("heuristic must be finite".into());
                }
                queue.push(QueueItem {
                    estimate,
                    cost: candidate,
                    node: edge.to,
                });
            }
        }
    }
    Ok(None)
}

/// Dijkstra is A* with a zero heuristic; kept separate for clarity at call sites.
pub fn dijkstra<F>(
    nodes: usize,
    start: usize,
    goal: usize,
    neighbors: F,
) -> Result<Option<SearchResult>, String>
where
    F: Fn(usize) -> Vec<Edge>,
{
    astar(nodes, start, goal, neighbors, |_| 0.0)
}
