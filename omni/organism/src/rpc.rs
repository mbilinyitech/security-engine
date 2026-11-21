//! JSON-RPC 2.0 dispatcher. One request per line, one response per line.

use serde_json::{json, Value};

use crate::algorithms::dp::knapsack;
use crate::algorithms::evolution::{evolve, GaConfig};
use crate::algorithms::graph::MemoryGraph;
use crate::algorithms::planning::{search as mcts_search, LineGame};
use crate::algorithms::search::{astar, Edge};
use crate::belief::{decide, Action, Bandit, BetaBelief};
use crate::calculus::{descend, numerical_gradient, simpson, Quadratic};
use crate::control::{ControlBoard, Homeostat, LoadMeter};
use crate::energy::EnergyMeter;
use crate::guard::{CircuitBreaker, RateLimiter};
use crate::memory::{MemoryItem, MemoryStore};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_ITERATIONS: usize = 10_000;
const MAX_NODES: usize = 100_000;

#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn number(params: &Value, key: &str) -> Result<f64, RpcError> {
    params
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| RpcError::invalid(format!("missing number parameter: {key}")))
}

fn optional_number(params: &Value, key: &str, default: f64) -> f64 {
    params.get(key).and_then(Value::as_f64).unwrap_or(default)
}

fn unsigned(params: &Value, key: &str) -> Result<u64, RpcError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid(format!("missing integer parameter: {key}")))
}

fn optional_unsigned(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn array<'a>(params: &'a Value, key: &str) -> Result<&'a Vec<Value>, RpcError> {
    params
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::invalid(format!("missing array parameter: {key}")))
}

fn unsigned_vec(params: &Value, key: &str) -> Result<Vec<u64>, RpcError> {
    array(params, key)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| RpcError::invalid(format!("{key} must contain integers")))
        })
        .collect()
}

fn f64_vec(params: &Value, key: &str) -> Result<Vec<f64>, RpcError> {
    array(params, key)?
        .iter()
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| RpcError::invalid(format!("{key} must contain numbers")))
        })
        .collect()
}

fn homes_from(params: &Value) -> Result<Vec<Homeostat>, RpcError> {
    let mut homes = Vec::new();
    for entry in array(params, "homes")? {
        homes.push(Homeostat {
            name: entry
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid("each homeostat needs a name"))?
                .to_string(),
            target: entry
                .get("target")
                .and_then(Value::as_f64)
                .ok_or_else(|| RpcError::invalid("each homeostat needs a numeric target"))?,
            current: entry.get("current").and_then(Value::as_f64).unwrap_or(0.0),
            tolerance: entry.get("tolerance").and_then(Value::as_f64).unwrap_or(1.0),
            weight: entry.get("weight").and_then(Value::as_f64).unwrap_or(1.0),
        });
    }
    Ok(homes)
}

fn actions_from(params: &Value) -> Result<Vec<Action>, RpcError> {
    let mut actions = Vec::new();
    for entry in array(params, "actions")? {
        actions.push(Action {
            name: entry
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid("each action needs a name"))?
                .to_string(),
            utility_success: entry
                .get("utility_success")
                .and_then(Value::as_f64)
                .ok_or_else(|| RpcError::invalid("each action needs utility_success"))?,
            utility_failure: entry
                .get("utility_failure")
                .and_then(Value::as_f64)
                .ok_or_else(|| RpcError::invalid("each action needs utility_failure"))?,
        });
    }
    Ok(actions)
}

fn build_adjacency(params: &Value, nodes: usize) -> Result<Vec<Vec<Edge>>, RpcError> {
    let mut adjacency = vec![Vec::new(); nodes];
    for entry in array(params, "edges")? {
        let tuple = entry
            .as_array()
            .ok_or_else(|| RpcError::invalid("each edge must be [from, to, cost]"))?;
        if tuple.len() != 3 {
            return Err(RpcError::invalid("each edge must be [from, to, cost]"));
        }
        let from = tuple[0]
            .as_u64()
            .ok_or_else(|| RpcError::invalid("edge.from must be an integer"))?
            as usize;
        let to = tuple[1]
            .as_u64()
            .ok_or_else(|| RpcError::invalid("edge.to must be an integer"))?
            as usize;
        let cost = tuple[2]
            .as_f64()
            .ok_or_else(|| RpcError::invalid("edge.cost must be a number"))?;
        if from >= nodes {
            return Err(RpcError::invalid("edge.from is out of range"));
        }
        adjacency[from].push(Edge { to, cost });
    }
    Ok(adjacency)
}

pub fn discover() -> Value {
    json!({
        "name": "organism",
        "version": VERSION,
        "protocol": "jsonrpc-2.0",
        "transport": "line-delimited stdio",
        "features": ["energy", "calculus", "search", "graph", "planning", "evolution", "dp"],
        "methods": [
            {
                "name": "organism.discover",
                "params": {},
                "returns": "this catalog"
            },
            {
                "name": "organism.state",
                "params": {},
                "returns": "{version, alive, methods}"
            },
            {
                "name": "energy.tick",
                "params": {
                    "capacity": "number > 0",
                    "starvation_threshold": "number in [0,1), default 0.2",
                    "level": "optional starting level",
                    "cost": "number >= 0",
                    "recharge": "number >= 0, default 0"
                },
                "returns": "{level, fraction, starving, dead}"
            },
            {
                "name": "homeostasis.step",
                "params": {
                    "target": "number",
                    "start": "number",
                    "weight": "number > 0, default 1",
                    "learning_rate": "number in (0, 1/weight), default 0.1",
                    "iterations": "integer <= 10000, default 100"
                },
                "returns": "{final, loss, gradient, steps, trajectory, losses}"
            },
            {
                "name": "calculus.integrate",
                "params": {
                    "a": "number",
                    "b": "number > a",
                    "n": "positive even integer <= 10000000, default 1000",
                    "integrand": "square | sine | exp"
                },
                "returns": "{integrand, a, b, n, value}"
            },
            {
                "name": "calculus.gradient_check",
                "params": {"target": "number", "weight": "number > 0", "x": "number", "h": "number > 0"},
                "returns": "{analytic, numeric, absolute_error}"
            },
            {
                "name": "search.astar",
                "params": {
                    "nodes": "integer <= 100000",
                    "start": "node index",
                    "goal": "node index",
                    "edges": "[[from, to, cost], ...]",
                    "heuristic": "optional [number] per node"
                },
                "returns": "{path, cost, expanded} or null"
            },
            {
                "name": "graph.pagerank",
                "params": {
                    "nodes": "integer <= 100000",
                    "labels": "optional [string] per node",
                    "edges": "[[from, to] or [from, to, weight], ...]",
                    "damping": "number in (0,1), default 0.85",
                    "iterations": "integer <= 100000, default 100",
                    "top_k": "integer, default 5"
                },
                "returns": "{scores, total, top}"
            },
            {
                "name": "plan.mcts",
                "params": {
                    "length": "integer >= 2 (line world)",
                    "iterations": "integer <= 1000000, default 2000",
                    "horizon": "integer, default length-2 (the deadline)",
                    "seed": "integer, default 7"
                },
                "returns": "{best_action, visits, mean_value, children}"
            },
            {
                "name": "evolve.ga",
                "params": {
                    "target": "[number] genes to match",
                    "population": "integer in [4,10000], default 60",
                    "generations": "integer <= 100000, default 100",
                    "mutation_rate": "number in [0,1], default 0.15",
                    "crossover_rate": "number in [0,1], default 0.5",
                    "elite": "integer, default 2",
                    "seed": "integer, default 11"
                },
                "returns": "{best_genes, best_fitness, best_distance, generations, best_history}"
            },
            {
                "name": "dp.knapsack",
                "params": {
                    "weights": "[integer]",
                    "values": "[integer]",
                    "capacity": "integer <= 200000"
                },
                "returns": "{best_value, total_weight, items}"
            },
            {
                "name": "control.signals",
                "params": {"homes": "[{name, target, current, tolerance, weight}]"},
                "returns": "{signals, dominant}"
            },
            {
                "name": "control.step",
                "params": {
                    "homes": "[{name, target, current, tolerance, weight}]",
                    "name": "homeostat to correct",
                    "gain": "number in (0,1], default 0.5",
                    "max_step": "number > 0, default 1"
                },
                "returns": "{value, signals}"
            },
            {
                "name": "load.charge",
                "params": {
                    "capacity": "number > 0",
                    "window_ms": "integer > 0",
                    "cost": "number >= 0",
                    "now_ms": "integer"
                },
                "returns": "{used, fraction, overheated, throttled}"
            },
            {
                "name": "belief.update",
                "params": {
                    "alpha": "number > 0, default 1",
                    "beta": "number > 0, default 1",
                    "successes": "integer, default 0",
                    "failures": "integer, default 0"
                },
                "returns": "{alpha, beta, mean, variance, entropy, observations, log_likelihood}"
            },
            {
                "name": "belief.decide",
                "params": {
                    "alpha": "number > 0",
                    "beta": "number > 0",
                    "actions": "[{name, utility_success, utility_failure}]"
                },
                "returns": "{best, expected}"
            },
            {
                "name": "memory.init",
                "params": {
                    "capacity": "integer in [1, 1000000]",
                    "decay_per_hour": "number in [0,1], default 0.02",
                    "floor": "number in (0,1), default 0.05"
                },
                "returns": "memory stats"
            },
            {
                "name": "memory.insert",
                "params": {
                    "content": "string",
                    "embedding": "[number]",
                    "now_ms": "integer",
                    "salience": "number in [0,1], default 0.5",
                    "emotion": "number in [-1,1], default 0"
                },
                "returns": "{id}"
            },
            {
                "name": "memory.search",
                "params": {"embedding": "[number]", "limit": "integer, default 5", "now_ms": "integer"},
                "returns": "[{id, score}]"
            },
            {
                "name": "memory.reinforce",
                "params": {"id": "integer", "now_ms": "integer"},
                "returns": "{ok}"
            },
            {
                "name": "memory.decay",
                "params": {"now_ms": "integer"},
                "returns": "{forgotten}"
            },
            {
                "name": "memory.consolidate",
                "params": {"threshold": "number in (0,1]", "now_ms": "integer"},
                "returns": "{merged}"
            },
            {
                "name": "memory.forget",
                "params": {"id": "integer"},
                "returns": "{ok}"
            },
            {
                "name": "memory.suppress",
                "params": {"id": "integer", "suppressed": "boolean"},
                "returns": "{ok}"
            },
            {
                "name": "memory.by_time",
                "params": {"from_ms": "integer", "to_ms": "integer"},
                "returns": "{ids}"
            },
            {
                "name": "memory.by_emotion",
                "params": {"min": "number", "max": "number"},
                "returns": "{ids}"
            },
            {
                "name": "memory.stats",
                "params": {},
                "returns": "{live, tombstoned, suppressed, capacity}"
            },
            {
                "name": "memory.snapshot",
                "params": {},
                "returns": "{items}"
            },
            {
                "name": "memory.restore",
                "params": {"items": "[memory item]"},
                "returns": "{restored}"
            },
            {
                "name": "bandit.init",
                "params": {"arms": "[string]"},
                "returns": "{arms}"
            },
            {
                "name": "bandit.select",
                "params": {},
                "returns": "{index, arm}"
            },
            {
                "name": "bandit.update",
                "params": {"index": "integer", "reward": "number in [0,1]"},
                "returns": "{ok}"
            },
            {
                "name": "guard.breaker.init",
                "params": {
                    "failure_threshold": "integer >= 1",
                    "cooldown_ms": "integer > 0",
                    "half_open_successes": "integer >= 1, default 2"
                },
                "returns": "{state, failures, opened_at_ms, allowed}"
            },
            {
                "name": "guard.breaker.allow",
                "params": {"now_ms": "integer"},
                "returns": "{allowed, status}"
            },
            {
                "name": "guard.breaker.record",
                "params": {"success": "boolean", "now_ms": "integer"},
                "returns": "{state, failures, opened_at_ms, allowed}"
            },
            {
                "name": "guard.breaker.status",
                "params": {"now_ms": "integer"},
                "returns": "{state, failures, opened_at_ms, allowed}"
            },
            {
                "name": "guard.rate.init",
                "params": {
                    "capacity": "number > 0",
                    "refill_per_second": "number >= 0",
                    "now_ms": "integer"
                },
                "returns": "{allowed, tokens, capacity}"
            },
            {
                "name": "guard.rate.acquire",
                "params": {"cost": "number > 0", "now_ms": "integer"},
                "returns": "{allowed, tokens, capacity}"
            },
            {
                "name": "guard.rate.status",
                "params": {},
                "returns": "{allowed, tokens, capacity}"
            }
        ]
    })
}

pub fn handle(request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return error_response(id, -32600, "jsonrpc must be \"2.0\"");
    }
    let method = match request.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => return error_response(id, -32600, "missing method"),
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    match dispatch(method, &params) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => error_response(id, error.code, &error.message),
    }
}

/// A stateful JSON-RPC session. Memory and bandit methods need state, so the
/// server keeps one session per connection.
pub struct Session {
    memory: Option<MemoryStore>,
    bandit: Option<Bandit>,
    breaker: Option<CircuitBreaker>,
    limiter: Option<RateLimiter>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            memory: None,
            bandit: None,
            breaker: None,
            limiter: None,
        }
    }

    pub fn handle(&mut self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return error_response(id, -32600, "jsonrpc must be \"2.0\"");
        }
        let method = match request.get("method").and_then(Value::as_str) {
            Some(method) => method.to_string(),
            None => return error_response(id, -32600, "missing method"),
        };
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        let result = if method.starts_with("memory.") && method != "memory.pagerank" {
            self.memory_call(&method, &params)
        } else if method.starts_with("bandit.") {
            self.bandit_call(&method, &params)
        } else if method.starts_with("guard.") {
            self.guard_call(&method, &params)
        } else {
            dispatch(&method, &params)
        };
        match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => error_response(id, error.code, &error.message),
        }
    }

    fn memory_call(&mut self, method: &str, params: &Value) -> Result<Value, RpcError> {
        if method == "memory.init" {
            let capacity = unsigned(params, "capacity")? as usize;
            let decay = optional_number(params, "decay_per_hour", 0.02);
            let floor = optional_number(params, "floor", 0.05);
            let store = MemoryStore::new(capacity, decay, floor).map_err(RpcError::invalid)?;
            let stats = store.stats();
            self.memory = Some(store);
            return Ok(json!(stats));
        }
        let store = self.memory.as_mut().ok_or_else(|| {
            RpcError::invalid("memory is not initialised: call memory.init first")
        })?;
        match method {
            "memory.insert" => {
                let content = params
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid("content must be a string"))?;
                let embedding = f64_vec(params, "embedding")?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let salience = optional_number(params, "salience", 0.5);
                let emotion = optional_number(params, "emotion", 0.0);
                let id = store
                    .insert(content, embedding, now_ms, salience, emotion)
                    .map_err(RpcError::invalid)?;
                Ok(json!({"id": id}))
            }
            "memory.get" => {
                let id = unsigned(params, "id")?;
                Ok(json!(store.get(id)))
            }
            "memory.search" => {
                let embedding = f64_vec(params, "embedding")?;
                let limit = optional_unsigned(params, "limit", 5) as usize;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let found = store
                    .search_similar(&embedding, limit, now_ms)
                    .map_err(RpcError::invalid)?;
                Ok(json!(found
                    .iter()
                    .map(|(id, score)| json!({"id": id, "score": score}))
                    .collect::<Vec<_>>()))
            }
            "memory.reinforce" => {
                let id = unsigned(params, "id")?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                store.reinforce(id, now_ms).map_err(RpcError::invalid)?;
                Ok(json!({"ok": true}))
            }
            "memory.decay" => {
                let now_ms = unsigned(params, "now_ms")? as i64;
                Ok(json!({"forgotten": store.decay_sweep(now_ms)}))
            }
            "memory.consolidate" => {
                let threshold = number(params, "threshold")?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let merged = store
                    .consolidate(threshold, now_ms)
                    .map_err(RpcError::invalid)?;
                Ok(json!({"merged": merged}))
            }
            "memory.forget" => {
                let id = unsigned(params, "id")?;
                store.forget(id).map_err(RpcError::invalid)?;
                Ok(json!({"ok": true}))
            }
            "memory.suppress" => {
                let id = unsigned(params, "id")?;
                let suppressed = params
                    .get("suppressed")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| RpcError::invalid("suppressed must be a boolean"))?;
                store.suppress(id, suppressed).map_err(RpcError::invalid)?;
                Ok(json!({"ok": true}))
            }
            "memory.by_time" => {
                let from_ms = unsigned(params, "from_ms")? as i64;
                let to_ms = unsigned(params, "to_ms")? as i64;
                Ok(json!({"ids": store.search_by_time(from_ms, to_ms)}))
            }
            "memory.by_emotion" => {
                let min = number(params, "min")?;
                let max = number(params, "max")?;
                Ok(json!({"ids": store.search_by_emotion(min, max)}))
            }
            "memory.snapshot" => Ok(json!({"items": store.snapshot()})),
            "memory.restore" => {
                let raw = array(params, "items")?;
                let mut items = Vec::with_capacity(raw.len());
                for entry in raw {
                    items.push(
                        serde_json::from_value::<MemoryItem>(entry.clone())
                            .map_err(|err| RpcError::invalid(format!("bad memory item: {err}")))?,
                    );
                }
                store.restore(items).map_err(RpcError::invalid)?;
                let stats = store.stats();
                Ok(json!({"restored": stats.live + stats.tombstoned}))
            }
            "memory.stats" => Ok(json!(store.stats())),
            "memory.purge" => Ok(json!({"purged": store.purge()})),
            other => Err(RpcError {
                code: -32601,
                message: format!("method not found: {other}"),
            }),
        }
    }

    fn bandit_call(&mut self, method: &str, params: &Value) -> Result<Value, RpcError> {
        if method == "bandit.init" {
            let mut names = Vec::new();
            for entry in array(params, "arms")? {
                names.push(
                    entry
                        .as_str()
                        .ok_or_else(|| RpcError::invalid("arms must be strings"))?
                        .to_string(),
                );
            }
            let bandit = Bandit::new(&names).map_err(RpcError::invalid)?;
            let count = bandit.arms().len();
            self.bandit = Some(bandit);
            return Ok(json!({"arms": count}));
        }
        let bandit = self
            .bandit
            .as_mut()
            .ok_or_else(|| RpcError::invalid("bandit is not initialised: call bandit.init first"))?;
        match method {
            "bandit.select" => {
                let index = bandit.select().map_err(RpcError::invalid)?;
                let name = bandit.arms()[index].name.clone();
                Ok(json!({"index": index, "arm": name}))
            }
            "bandit.update" => {
                let index = unsigned(params, "index")? as usize;
                let reward = number(params, "reward")?;
                bandit.update(index, reward).map_err(RpcError::invalid)?;
                Ok(json!({"ok": true}))
            }
            "bandit.arms" => Ok(json!(bandit.arms())),
            other => Err(RpcError {
                code: -32601,
                message: format!("method not found: {other}"),
            }),
        }
    }

    fn guard_call(&mut self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "guard.breaker.init" => {
                let threshold = unsigned(params, "failure_threshold")?;
                if threshold > u32::MAX as u64 {
                    return Err(RpcError::invalid("failure_threshold is too large"));
                }
                let cooldown = unsigned(params, "cooldown_ms")? as i64;
                let half_open = optional_unsigned(params, "half_open_successes", 2);
                if half_open > u32::MAX as u64 {
                    return Err(RpcError::invalid("half_open_successes is too large"));
                }
                let breaker = CircuitBreaker::new(threshold as u32, cooldown, half_open as u32)
                    .map_err(RpcError::invalid)?;
                let status = breaker.status(0);
                self.breaker = Some(breaker);
                Ok(json!(status))
            }
            "guard.breaker.allow" => {
                let now_ms = unsigned(params, "now_ms")? as i64;
                let breaker = self.breaker.as_mut().ok_or_else(|| {
                    RpcError::invalid("breaker is not initialised: call guard.breaker.init first")
                })?;
                let allowed = breaker.allow(now_ms);
                let status = breaker.status(now_ms);
                Ok(json!({"allowed": allowed, "status": status}))
            }
            "guard.breaker.record" => {
                let success = params
                    .get("success")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| RpcError::invalid("success must be a boolean"))?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let breaker = self.breaker.as_mut().ok_or_else(|| {
                    RpcError::invalid("breaker is not initialised: call guard.breaker.init first")
                })?;
                breaker.record(success, now_ms);
                Ok(json!(breaker.status(now_ms)))
            }
            "guard.breaker.status" => {
                let now_ms = unsigned(params, "now_ms")? as i64;
                let breaker = self.breaker.as_ref().ok_or_else(|| {
                    RpcError::invalid("breaker is not initialised: call guard.breaker.init first")
                })?;
                Ok(json!(breaker.status(now_ms)))
            }
            "guard.rate.init" => {
                let capacity = number(params, "capacity")?;
                let refill = number(params, "refill_per_second")?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let limiter = RateLimiter::new(capacity, refill, now_ms).map_err(RpcError::invalid)?;
                let status = limiter.status();
                self.limiter = Some(limiter);
                Ok(json!(status))
            }
            "guard.rate.acquire" => {
                let cost = number(params, "cost")?;
                let now_ms = unsigned(params, "now_ms")? as i64;
                let limiter = self.limiter.as_mut().ok_or_else(|| {
                    RpcError::invalid("limiter is not initialised: call guard.rate.init first")
                })?;
                let status = limiter.try_acquire(cost, now_ms).map_err(RpcError::invalid)?;
                Ok(json!(status))
            }
            "guard.rate.status" => {
                let limiter = self.limiter.as_ref().ok_or_else(|| {
                    RpcError::invalid("limiter is not initialised: call guard.rate.init first")
                })?;
                Ok(json!(limiter.status()))
            }
            other => Err(RpcError {
                code: -32601,
                message: format!("method not found: {other}"),
            }),
        }
    }
}

fn dispatch(method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "organism.discover" => Ok(discover()),
        "organism.state" => Ok(json!({
            "version": VERSION,
            "alive": true,
            "methods": discover()["methods"].clone(),
        })),
        "energy.tick" => {
            let capacity = number(params, "capacity")?;
            let threshold = optional_number(params, "starvation_threshold", 0.2);
            let cost = number(params, "cost")?;
            let recharge = optional_number(params, "recharge", 0.0);
            let mut meter = EnergyMeter::new(capacity, threshold).map_err(RpcError::invalid)?;
            if let Some(level) = params.get("level").and_then(Value::as_f64) {
                let drain = (capacity - level).max(0.0);
                meter.consume(drain).map_err(RpcError::invalid)?;
            }
            let report = meter.tick(cost, recharge).map_err(RpcError::invalid)?;
            Ok(json!(report))
        }
        "homeostasis.step" => {
            let target = number(params, "target")?;
            let weight = optional_number(params, "weight", 1.0);
            let start = number(params, "start")?;
            let learning_rate = optional_number(params, "learning_rate", 0.1);
            let iterations = optional_unsigned(params, "iterations", 100) as usize;
            if iterations > MAX_ITERATIONS {
                return Err(RpcError::invalid(format!(
                    "iterations above {MAX_ITERATIONS} are refused"
                )));
            }
            let objective = Quadratic::new(target, weight).map_err(RpcError::invalid)?;
            let trajectory =
                descend(&objective, start, learning_rate, iterations).map_err(RpcError::invalid)?;
            let final_x = *trajectory.xs.last().expect("trajectory is never empty");
            Ok(json!({
                "final": final_x,
                "loss": objective.loss(final_x),
                "gradient": objective.gradient(final_x),
                "steps": trajectory.xs.len() - 1,
                "trajectory": trajectory.xs,
                "losses": trajectory.losses,
            }))
        }
        "calculus.integrate" => {
            let a = number(params, "a")?;
            let b = number(params, "b")?;
            let n = optional_unsigned(params, "n", 1000) as usize;
            if n > 10_000_000 {
                return Err(RpcError::invalid("n above 10000000 is refused"));
            }
            let kind = params
                .get("integrand")
                .and_then(Value::as_str)
                .unwrap_or("square");
            let f: fn(f64) -> f64 = match kind {
                "square" => |x: f64| x * x,
                "sine" => |x: f64| x.sin(),
                "exp" => |x: f64| x.exp(),
                other => {
                    return Err(RpcError::invalid(format!("unknown integrand: {other}")));
                }
            };
            let value = simpson(f, a, b, n).map_err(RpcError::invalid)?;
            Ok(json!({"integrand": kind, "a": a, "b": b, "n": n, "value": value}))
        }
        "calculus.gradient_check" => {
            let target = number(params, "target")?;
            let weight = optional_number(params, "weight", 1.0);
            let x = number(params, "x")?;
            let h = optional_number(params, "h", 1e-5);
            let objective = Quadratic::new(target, weight).map_err(RpcError::invalid)?;
            let analytic = objective.gradient(x);
            let numeric = numerical_gradient(|value| objective.loss(value), x, h)
                .map_err(RpcError::invalid)?;
            Ok(json!({
                "analytic": analytic,
                "numeric": numeric,
                "absolute_error": (analytic - numeric).abs(),
            }))
        }
        "search.astar" => {
            let nodes = unsigned(params, "nodes")? as usize;
            if nodes == 0 || nodes > MAX_NODES {
                return Err(RpcError::invalid(format!(
                    "nodes must be in [1, {MAX_NODES}]"
                )));
            }
            let start = unsigned(params, "start")? as usize;
            let goal = unsigned(params, "goal")? as usize;
            let adjacency = build_adjacency(params, nodes)?;
            let heuristic = params.get("heuristic").and_then(Value::as_array).cloned();
            if let Some(values) = &heuristic {
                if values.len() != nodes {
                    return Err(RpcError::invalid("heuristic length must equal nodes"));
                }
            }
            let result = astar(
                nodes,
                start,
                goal,
                |node| adjacency[node].clone(),
                |node| {
                    heuristic
                        .as_ref()
                        .and_then(|values| values.get(node))
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                },
            )
            .map_err(RpcError::invalid)?;
            Ok(json!(result))
        }
        "graph.pagerank" | "memory.pagerank" => {
            let nodes = unsigned(params, "nodes")? as usize;
            if nodes == 0 || nodes > MAX_NODES {
                return Err(RpcError::invalid(format!(
                    "nodes must be in [1, {MAX_NODES}]"
                )));
            }
            let labels = params.get("labels").and_then(Value::as_array).cloned();
            let mut graph = MemoryGraph::new();
            for index in 0..nodes {
                let label = labels
                    .as_ref()
                    .and_then(|values| values.get(index))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("node-{index}"));
                graph.add_node(label);
            }
            for entry in array(params, "edges")? {
                let tuple = entry.as_array().ok_or_else(|| {
                    RpcError::invalid("each edge must be [from, to] or [from, to, weight]")
                })?;
                if tuple.len() < 2 {
                    return Err(RpcError::invalid("each edge needs at least from and to"));
                }
                let from = tuple[0]
                    .as_u64()
                    .ok_or_else(|| RpcError::invalid("edge.from must be an integer"))?
                    as usize;
                let to = tuple[1]
                    .as_u64()
                    .ok_or_else(|| RpcError::invalid("edge.to must be an integer"))?
                    as usize;
                let weight = tuple.get(2).and_then(Value::as_f64).unwrap_or(1.0);
                graph.add_edge(from, to, weight).map_err(RpcError::invalid)?;
            }
            let damping = optional_number(params, "damping", 0.85);
            let iterations = optional_unsigned(params, "iterations", 100) as usize;
            if iterations == 0 || iterations > MAX_NODES {
                return Err(RpcError::invalid("iterations must be in [1, 100000]"));
            }
            let scores = graph
                .pagerank(damping, iterations, 1e-10)
                .map_err(RpcError::invalid)?;
            let top_k = (optional_unsigned(params, "top_k", 5) as usize).min(nodes);
            Ok(json!({
                "scores": scores,
                "total": scores.iter().sum::<f64>(),
                "top": graph.ranked(&scores, top_k),
            }))
        }
        "plan.mcts" => {
            let length = unsigned(params, "length")? as usize;
            let iterations = optional_unsigned(params, "iterations", 2000) as u32;
            if iterations == 0 || iterations > 1_000_000 {
                return Err(RpcError::invalid("iterations must be in [1, 1000000]"));
            }
            let horizon =
                optional_unsigned(params, "horizon", length.saturating_sub(2).max(1) as u64)
                    as usize;
            let seed = optional_unsigned(params, "seed", 7);
            let game = LineGame::new(length).map_err(RpcError::invalid)?;
            let report = mcts_search(&game, iterations, horizon, seed).map_err(RpcError::invalid)?;
            Ok(json!(report))
        }
        "evolve.ga" => {
            let mut target = Vec::new();
            for value in array(params, "target")? {
                target.push(
                    value
                        .as_f64()
                        .ok_or_else(|| RpcError::invalid("target genes must be numbers"))?,
                );
            }
            let config = GaConfig {
                population: optional_unsigned(params, "population", 60) as usize,
                generations: optional_unsigned(params, "generations", 100) as usize,
                mutation_rate: optional_number(params, "mutation_rate", 0.15),
                crossover_rate: optional_number(params, "crossover_rate", 0.5),
                elite: optional_unsigned(params, "elite", 2) as usize,
                seed: optional_unsigned(params, "seed", 11),
            };
            let report = evolve(&target, &config, |genes| {
                -genes
                    .iter()
                    .zip(&target)
                    .map(|(gene, want)| (gene - want).powi(2))
                    .sum::<f64>()
            })
            .map_err(RpcError::invalid)?;
            Ok(json!({
                "best_genes": report.best.genes,
                "best_fitness": report.best.fitness,
                "best_distance": (-report.best.fitness).max(0.0),
                "generations": report.best_history.len(),
                "best_history": report.best_history,
            }))
        }
        "dp.knapsack" => {
            let weights = unsigned_vec(params, "weights")?;
            let values = unsigned_vec(params, "values")?;
            let capacity = unsigned(params, "capacity")?;
            let result = knapsack(&weights, &values, capacity).map_err(RpcError::invalid)?;
            Ok(json!(result))
        }
        "control.signals" => {
            let board = ControlBoard::new(homes_from(params)?).map_err(RpcError::invalid)?;
            Ok(json!({
                "signals": board.signals(),
                "dominant": board.dominant(),
            }))
        }
        "control.step" => {
            let mut board = ControlBoard::new(homes_from(params)?).map_err(RpcError::invalid)?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid("name is required"))?;
            let gain = optional_number(params, "gain", 0.5);
            let max_step = optional_number(params, "max_step", 1.0);
            let value = board.step(name, gain, max_step).map_err(RpcError::invalid)?;
            Ok(json!({"value": value, "signals": board.signals()}))
        }
        "load.charge" => {
            let capacity = number(params, "capacity")?;
            let window_ms = unsigned(params, "window_ms")? as i64;
            let cost = number(params, "cost")?;
            let now_ms = unsigned(params, "now_ms")? as i64;
            let mut meter = LoadMeter::new(capacity, window_ms).map_err(RpcError::invalid)?;
            let load = meter.charge(cost, now_ms).map_err(RpcError::invalid)?;
            Ok(json!(load))
        }
        "belief.update" => {
            let alpha = optional_number(params, "alpha", 1.0);
            let beta = optional_number(params, "beta", 1.0);
            let successes = optional_unsigned(params, "success_count", 0);
            let failures = optional_unsigned(params, "failure_count", 0);
            if successes > 1_000_000 || failures > 1_000_000 {
                return Err(RpcError::invalid("counts above 1000000 are refused"));
            }
            let mut belief = BetaBelief::new(alpha, beta).map_err(RpcError::invalid)?;
            let log_likelihood = belief
                .log_likelihood(successes as u32, failures as u32)
                .map_err(RpcError::invalid)?;
            belief.observe_batch(successes as u32, failures as u32);
            let summary = belief.summary().map_err(RpcError::invalid)?;
            let mut result = json!(summary);
            result["log_likelihood"] = json!(log_likelihood);
            Ok(result)
        }
        "belief.decide" => {
            let alpha = optional_number(params, "alpha", 1.0);
            let beta = optional_number(params, "beta", 1.0);
            let belief = BetaBelief::new(alpha, beta).map_err(RpcError::invalid)?;
            let actions = actions_from(params)?;
            let (best, expected) = decide(&belief, &actions).map_err(RpcError::invalid)?;
            Ok(json!({"best": best, "expected": expected}))
        }
        other => Err(RpcError {
            code: -32601,
            message: format!("method not found: {other}"),
        }),
    }
}
