use organism_core::algorithms::dp::knapsack;
use organism_core::algorithms::evolution::{evolve, GaConfig};
use organism_core::algorithms::graph::MemoryGraph;
use organism_core::algorithms::planning::{search as mcts, LineGame, Rng};
use organism_core::algorithms::search::{astar, dijkstra, Edge};
use organism_core::calculus::{descend, numerical_gradient, simpson, Adam, Quadratic};
use organism_core::energy::EnergyMeter;
use organism_core::rpc;
use serde_json::json;

fn line_graph(edges: &[(usize, usize, f64)]) -> impl Fn(usize) -> Vec<Edge> + '_ {
    move |node| {
        edges
            .iter()
            .filter(|(from, _, _)| *from == node)
            .map(|(_, to, cost)| Edge { to: *to, cost: *cost })
            .collect()
    }
}

#[test]
fn energy_clamps_at_bounds() {
    let mut meter = EnergyMeter::new(10.0, 0.2).unwrap();
    assert_eq!(meter.recharge(5.0).unwrap(), 0.0);
    assert_eq!(meter.consume(4.0).unwrap(), 4.0);
    assert_eq!(meter.level(), 6.0);
    assert_eq!(meter.consume(100.0).unwrap(), 6.0);
    assert!(meter.is_dead());
}

#[test]
fn energy_reports_starvation_and_death() {
    let mut meter = EnergyMeter::new(10.0, 0.5).unwrap();
    let report = meter.tick(6.0, 0.0).unwrap();
    assert!(report.starving);
    assert!(!report.dead);
    let report = meter.tick(4.0, 0.0).unwrap();
    assert!(report.dead);
}

#[test]
fn energy_rejects_non_finite_input() {
    assert!(EnergyMeter::new(f64::NAN, 0.2).is_err());
    let mut meter = EnergyMeter::new(10.0, 0.2).unwrap();
    assert!(meter.consume(f64::INFINITY).is_err());
    assert!(meter.consume(-1.0).is_err());
}

#[test]
fn gradient_descent_converges_to_target() {
    let objective = Quadratic::new(2.5, 1.0).unwrap();
    let trajectory = descend(&objective, -3.0, 0.4, 200).unwrap();
    let final_x = *trajectory.xs.last().unwrap();
    assert!((final_x - 2.5).abs() < 1e-9, "final = {final_x}");
    assert!(trajectory.losses.last().unwrap() < &1e-15);
}

#[test]
fn analytic_gradient_matches_numerical() {
    let objective = Quadratic::new(-1.25, 3.0).unwrap();
    for x in [-2.0, 0.0, 0.5, 4.0] {
        let analytic = objective.gradient(x);
        let numeric = numerical_gradient(|value| objective.loss(value), x, 1e-6).unwrap();
        assert!((analytic - numeric).abs() < 1e-6, "x = {x}");
    }
}

#[test]
fn gradient_descent_rejects_divergent_learning_rate() {
    let objective = Quadratic::new(1.0, 2.0).unwrap();
    assert!(descend(&objective, 0.0, 1.0, 10).is_err());
    assert!(descend(&objective, 0.0, 0.49, 10).is_ok());
}

#[test]
fn adam_converges_on_quadratic() {
    let objective = Quadratic::new(1.5, 1.0).unwrap();
    let mut adam = Adam::new();
    let mut x = 0.0;
    for _ in 0..2000 {
        x = adam.step(x, objective.gradient(x), 0.05);
    }
    assert!((x - 1.5).abs() < 1e-4, "x = {x}");
}

#[test]
fn simpson_is_exact_for_cubic_polynomials() {
    let square = simpson(|x| x * x, 0.0, 1.0, 100).unwrap();
    assert!((square - 1.0 / 3.0).abs() < 1e-12);
    let cubic = simpson(|x| x * x * x, 0.0, 2.0, 100).unwrap();
    assert!((cubic - 4.0).abs() < 1e-12);
}

#[test]
fn simpson_rejects_odd_intervals() {
    assert!(simpson(|x| x, 0.0, 1.0, 3).is_err());
    assert!(simpson(|x| x, 1.0, 1.0, 4).is_err());
}

#[test]
fn astar_finds_the_cheapest_path() {
    let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 5.0), (2, 3, 1.0), (1, 3, 9.0)];
    let neighbors = line_graph(&edges);
    let result = astar(4, 0, 3, neighbors, |_| 0.0).unwrap().unwrap();
    assert_eq!(result.path, vec![0, 1, 2, 3]);
    assert!((result.cost - 3.0).abs() < 1e-12);
}

#[test]
fn astar_returns_none_when_unreachable() {
    let edges = [(0, 1, 1.0)];
    let neighbors = line_graph(&edges);
    assert!(astar(3, 0, 2, neighbors, |_| 0.0).unwrap().is_none());
}

#[test]
fn astar_rejects_negative_costs() {
    let edges = [(0, 1, -1.0)];
    let neighbors = line_graph(&edges);
    assert!(astar(2, 0, 1, neighbors, |_| 0.0).is_err());
}

#[test]
fn dijkstra_agrees_with_astar() {
    let edges = [(0, 1, 2.0), (1, 2, 2.0), (0, 2, 10.0), (2, 3, 1.0)];
    let a = astar(4, 0, 3, line_graph(&edges), |_| 0.0).unwrap().unwrap();
    let d = dijkstra(4, 0, 3, line_graph(&edges)).unwrap().unwrap();
    assert!((a.cost - d.cost).abs() < 1e-12);
}

#[test]
fn pagerank_scores_sum_to_one() {
    let mut graph = MemoryGraph::new();
    for label in ["a", "b", "c", "d"] {
        graph.add_node(label);
    }
    graph.add_edge(0, 1, 1.0).unwrap();
    graph.add_edge(1, 2, 1.0).unwrap();
    graph.add_edge(2, 0, 1.0).unwrap();
    let scores = graph.pagerank(0.85, 200, 1e-12).unwrap();
    let total: f64 = scores.iter().sum();
    assert!((total - 1.0).abs() < 1e-9, "total = {total}");
}

#[test]
fn pagerank_ranks_the_hub_highest() {
    let mut graph = MemoryGraph::new();
    for label in ["hub", "a", "b", "c"] {
        graph.add_node(label);
    }
    for from in 1..4 {
        graph.add_edge(from, 0, 1.0).unwrap();
    }
    let scores = graph.pagerank(0.85, 200, 1e-12).unwrap();
    let ranked = graph.ranked(&scores, 4);
    assert_eq!(ranked[0].label, "hub");
}

#[test]
fn pagerank_handles_dangling_nodes() {
    let mut graph = MemoryGraph::new();
    graph.add_node("only");
    let scores = graph.pagerank(0.85, 50, 1e-12).unwrap();
    assert!((scores[0] - 1.0).abs() < 1e-12);
}

#[test]
fn pagerank_rejects_bad_parameters() {
    let mut graph = MemoryGraph::new();
    graph.add_node("a");
    assert!(graph.pagerank(1.0, 10, 1e-9).is_err());
    assert!(graph.pagerank(0.85, 0, 1e-9).is_err());
}

#[test]
fn mcts_moves_towards_the_goal() {
    let game = LineGame::new(12).unwrap();
    for seed in 1..=5 {
        let report = mcts(&game, 2000, 10, seed).unwrap();
        assert_eq!(report.best_action, 1, "seed = {seed}");
    }
}

#[test]
fn mcts_is_deterministic_for_a_seed() {
    let game = LineGame::new(9).unwrap();
    let first = mcts(&game, 500, 18, 42).unwrap();
    let second = mcts(&game, 500, 18, 42).unwrap();
    assert_eq!(first.best_action, second.best_action);
    assert_eq!(first.visits, second.visits);
    assert_eq!(first.children.len(), second.children.len());
}

#[test]
fn rng_is_reproducible() {
    let mut a = Rng::new(7);
    let mut b = Rng::new(7);
    for _ in 0..100 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn genetic_algorithm_approaches_the_target() {
    let target = [0.3, -0.7, 1.1];
    let config = GaConfig {
        population: 80,
        generations: 150,
        mutation_rate: 0.2,
        crossover_rate: 0.5,
        elite: 4,
        seed: 3,
    };
    let report = evolve(&target, &config, |genes| {
        -genes
            .iter()
            .zip(&target)
            .map(|(gene, want)| (gene - want).powi(2))
            .sum::<f64>()
    })
    .unwrap();
    let distance = (-report.best.fitness).max(0.0);
    assert!(distance < 1e-3, "distance = {distance}");
    assert_eq!(report.best_history.len(), 150);
}

#[test]
fn genetic_algorithm_is_deterministic() {
    let target = [0.1, 0.2];
    let config = GaConfig {
        population: 20,
        generations: 20,
        mutation_rate: 0.1,
        crossover_rate: 0.5,
        elite: 2,
        seed: 99,
    };
    let fitness = |genes: &[f64]| -genes.iter().map(|g| g * g).sum::<f64>();
    let first = evolve(&target, &config, fitness).unwrap();
    let second = evolve(&target, &config, fitness).unwrap();
    assert_eq!(first.best.genes, second.best.genes);
}

#[test]
fn knapsack_finds_the_known_optimum() {
    let result = knapsack(&[12, 7, 11, 8, 9], &[24, 13, 23, 15, 16], 26).unwrap();
    assert_eq!(result.best_value, 51);
    assert!(result.total_weight <= 26);
}

#[test]
fn knapsack_reconstruction_is_consistent() {
    let weights = [3, 4, 5, 8];
    let values = [4, 5, 8, 9];
    let result = knapsack(&weights, &values, 12).unwrap();
    let recomputed: u64 = result.items.iter().map(|&index| values[index]).sum();
    let weight: u64 = result.items.iter().map(|&index| weights[index]).sum();
    assert_eq!(recomputed, result.best_value);
    assert_eq!(weight, result.total_weight);
    assert!(weight <= 12);
}

#[test]
fn knapsack_rejects_mismatched_inputs() {
    assert!(knapsack(&[1, 2], &[1], 3).is_err());
    assert!(knapsack(&[1], &[1], 1_000_000).is_err());
}

#[test]
fn rpc_discover_lists_every_method() {
    let catalog = rpc::discover();
    let methods = catalog["methods"].as_array().unwrap();
    let names: Vec<&str> = methods
        .iter()
        .map(|method| method["name"].as_str().unwrap())
        .collect();
    for expected in [
        "organism.discover",
        "energy.tick",
        "homeostasis.step",
        "search.astar",
        "graph.pagerank",
        "plan.mcts",
        "evolve.ga",
        "dp.knapsack",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[test]
fn rpc_unknown_method_returns_32601() {
    let response = rpc::handle(&json!({"jsonrpc": "2.0", "id": 9, "method": "nope"}));
    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["id"], 9);
}

#[test]
fn rpc_invalid_request_returns_32600() {
    let response = rpc::handle(&json!({"id": 1, "method": "organism.discover"}));
    assert_eq!(response["error"]["code"], -32600);
}

#[test]
fn rpc_invalid_params_returns_32602() {
    let response = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "energy.tick",
        "params": {"capacity": 10.0}
    }));
    assert_eq!(response["error"]["code"], -32602);
}

#[test]
fn rpc_energy_tick_computes_a_level() {
    let response = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "energy.tick",
        "params": {"capacity": 10.0, "cost": 4.0, "recharge": 1.0}
    }));
    assert_eq!(response["result"]["level"], 7.0);
}

#[test]
fn rpc_astar_returns_a_path() {
    let response = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "search.astar",
        "params": {
            "nodes": 3,
            "start": 0,
            "goal": 2,
            "edges": [[0, 1, 1.0], [1, 2, 1.0], [0, 2, 5.0]]
        }
    }));
    assert_eq!(response["result"]["path"], json!([0, 1, 2]));
    assert_eq!(response["result"]["cost"], 2.0);
}

#[test]
fn rpc_pagerank_totals_one() {
    let response = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "graph.pagerank",
        "params": {"nodes": 3, "edges": [[0, 1], [1, 2], [2, 0]], "top_k": 3}
    }));
    let total = response["result"]["total"].as_f64().unwrap();
    assert!((total - 1.0).abs() < 1e-9);
}

#[test]
fn rpc_homeostasis_converges() {
    let response = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "homeostasis.step",
        "params": {"target": 1.0, "start": 0.0, "learning_rate": 0.3, "iterations": 50}
    }));
    let final_x = response["result"]["final"].as_f64().unwrap();
    assert!((final_x - 1.0).abs() < 1e-6, "final = {final_x}");
}

#[test]
fn rpc_ga_and_knapsack_respond() {
    let ga = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "evolve.ga",
        "params": {"target": [0.5, -0.5], "generations": 40, "population": 30, "seed": 5}
    }));
    assert!(ga["result"]["best_distance"].as_f64().unwrap() < 0.5);

    let packed = rpc::handle(&json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "dp.knapsack",
        "params": {"weights": [1, 3, 4, 5], "values": [1, 4, 5, 7], "capacity": 7}
    }));
    assert_eq!(packed["result"]["best_value"], 9);
}

// ---- memory ----

#[test]
fn memory_decays_and_reinforcement_restores_strength() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.5, 0.05).unwrap();
    let id = store.insert("mkutano", vec![1.0, 0.0], 0, 0.5, 0.0).unwrap();
    let fresh = store.strength(id, 0).unwrap();
    let hour_later = store.strength(id, 3_600_000).unwrap();
    assert!(hour_later < fresh, "decay must reduce strength");
    store.reinforce(id, 3_600_000).unwrap();
    let reinforced = store.strength(id, 3_600_000).unwrap();
    assert!(reinforced > hour_later, "reinforcement must help");
}

#[test]
fn memory_search_orders_by_similarity_times_strength() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.0, 0.05).unwrap();
    let near = store.insert("karibu", vec![1.0, 0.0, 0.0], 0, 1.0, 0.0).unwrap();
    let far = store.insert("mbali", vec![0.0, 1.0, 0.0], 0, 1.0, 0.0).unwrap();
    let found = store.search_similar(&[0.9, 0.1, 0.0], 2, 0).unwrap();
    assert_eq!(found[0].0, near);
    assert_eq!(found[1].0, far);
    assert!(found[0].1 > found[1].1);
}

#[test]
fn memory_capacity_evicts_the_weakest() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(2, 0.0, 0.05).unwrap();
    store.insert("strong", vec![1.0], 0, 0.9, 0.0).unwrap();
    store.insert("weak", vec![1.0], 0, 0.1, 0.0).unwrap();
    store.insert("new", vec![1.0], 0, 0.5, 0.0).unwrap();
    let stats = store.stats();
    assert_eq!(stats.live, 2);
    assert_eq!(stats.tombstoned, 1);
}

#[test]
fn memory_consolidation_merges_duplicates() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.0, 0.05).unwrap();
    store.insert("a", vec![1.0, 0.0], 0, 0.8, 0.0).unwrap();
    store.insert("b", vec![1.0, 0.0], 0, 0.6, 0.0).unwrap();
    let merged = store.consolidate(0.99, 0).unwrap();
    assert_eq!(merged, 1);
    assert_eq!(store.stats().live, 1);
}

#[test]
fn memory_suppression_hides_items_from_search() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.0, 0.05).unwrap();
    let id = store.insert("kiwewe", vec![1.0], 0, 1.0, -0.9).unwrap();
    store.suppress(id, true).unwrap();
    assert!(store.search_similar(&[1.0], 5, 0).unwrap().is_empty());
    store.suppress(id, false).unwrap();
    assert_eq!(store.search_similar(&[1.0], 5, 0).unwrap().len(), 1);
}

#[test]
fn memory_forget_keeps_a_tombstone_until_purged() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.0, 0.05).unwrap();
    let id = store.insert("a", vec![1.0], 0, 1.0, 0.0).unwrap();
    store.forget(id).unwrap();
    assert_eq!(store.stats().live, 0);
    assert_eq!(store.stats().tombstoned, 1);
    assert_eq!(store.purge(), 1);
    assert_eq!(store.stats().tombstoned, 0);
}

#[test]
fn memory_time_and_emotion_lookups() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(16, 0.0, 0.05).unwrap();
    let early = store.insert("a", vec![1.0], 1_000, 0.5, 0.9).unwrap();
    let late = store.insert("b", vec![1.0], 5_000, 0.5, -0.9).unwrap();
    assert_eq!(store.search_by_time(0, 2_000), vec![early]);
    assert_eq!(store.search_by_emotion(0.5, 1.0), vec![early]);
    assert_eq!(store.search_by_emotion(-1.0, -0.5), vec![late]);
}

#[test]
fn memory_rejects_bad_input() {
    use organism_core::memory::MemoryStore;
    assert!(MemoryStore::new(0, 0.1, 0.05).is_err());
    let mut store = MemoryStore::new(4, 0.1, 0.05).unwrap();
    assert!(store.insert("x", vec![], 0, 0.5, 0.0).is_err());
    assert!(store.insert("x", vec![f64::NAN], 0, 0.5, 0.0).is_err());
    assert!(store.insert("x", vec![1.0], 0, 1.5, 0.0).is_err());
    assert!(store.insert("x", vec![1.0], 0, 0.5, 2.0).is_err());
    assert!(store.search_similar(&[], 3, 0).is_err());
}

// ---- control ----

#[test]
fn control_signals_expose_deficit_and_urgency() {
    use organism_core::control::{ControlBoard, Homeostat};
    let board = ControlBoard::new(vec![
        Homeostat {
            name: "energy".into(),
            target: 0.8,
            current: 0.3,
            tolerance: 0.2,
            weight: 2.0,
        },
        Homeostat {
            name: "novelty".into(),
            target: 0.5,
            current: 0.5,
            tolerance: 0.1,
            weight: 1.0,
        },
    ])
    .unwrap();
    let signals = board.signals();
    assert!((signals[0].error - 2.5).abs() < 1e-12);
    assert_eq!(signals[0].urgency, 1.0);
    assert!(!signals[0].satisfied);
    assert!(signals[1].satisfied);
    assert_eq!(board.dominant().unwrap().name, "energy");
}

#[test]
fn control_step_respects_the_cap() {
    use organism_core::control::{ControlBoard, Homeostat};
    let mut board = ControlBoard::new(vec![Homeostat {
        name: "energy".into(),
        target: 1.0,
        current: 0.0,
        tolerance: 0.1,
        weight: 1.0,
    }])
    .unwrap();
    let value = board.step("energy", 1.0, 0.25).unwrap();
    assert!((value - 0.25).abs() < 1e-12);
    assert!(board.step("energy", 0.0, 0.1).is_err());
    assert!(board.step("energy", 1.0, -1.0).is_err());
    assert!(board.step("missing", 0.5, 0.1).is_err());
}

#[test]
fn control_rejects_duplicate_names() {
    use organism_core::control::{ControlBoard, Homeostat};
    let home = Homeostat {
        name: "energy".into(),
        target: 1.0,
        current: 0.0,
        tolerance: 0.1,
        weight: 1.0,
    };
    assert!(ControlBoard::new(vec![home.clone(), home]).is_err());
}

#[test]
fn load_meter_throttles_then_overheats_and_resets() {
    use organism_core::control::LoadMeter;
    let mut meter = LoadMeter::new(100.0, 1_000).unwrap();
    let load = meter.charge(50.0, 0).unwrap();
    assert!(!load.throttled);
    let load = meter.charge(40.0, 10).unwrap();
    assert!(load.throttled && !load.overheated);
    let load = meter.charge(20.0, 20).unwrap();
    assert!(load.overheated);
    let load = meter.charge(10.0, 2_000).unwrap();
    assert_eq!(load.used, 10.0, "a new window resets the meter");
}

// ---- belief ----

#[test]
fn ln_gamma_matches_known_factorials() {
    use organism_core::belief::ln_gamma;
    assert!((ln_gamma(5.0).unwrap() - 24f64.ln()).abs() < 1e-9);
    assert!((ln_gamma(1.0).unwrap()).abs() < 1e-12);
    assert!(ln_gamma(0.0).is_err());
}

#[test]
fn digamma_matches_known_values() {
    use organism_core::belief::digamma;
    assert!((digamma(1.0).unwrap() + std::f64::consts::EULER_GAMMA).abs() < 1e-8);
    assert!((digamma(10.0).unwrap() - 2.251_752_682_037_563).abs() < 1e-7);
}

#[test]
fn beta_entropy_matches_closed_form_values() {
    use organism_core::belief::BetaBelief;
    let uniform = BetaBelief::new(1.0, 1.0).unwrap();
    assert!(uniform.entropy().unwrap().abs() < 1e-9);
    let arcsine = BetaBelief::new(0.5, 0.5).unwrap();
    let expected = (std::f64::consts::PI / 4.0).ln();
    assert!((arcsine.entropy().unwrap() - expected).abs() < 1e-7);
}

#[test]
fn belief_updates_move_the_mean() {
    use organism_core::belief::BetaBelief;
    let mut belief = BetaBelief::new(1.0, 1.0).unwrap();
    for _ in 0..7 {
        belief.observe(true);
    }
    for _ in 0..3 {
        belief.observe(false);
    }
    // Prior Beta(1,1) plus 7 successes and 3 failures gives 8/12.
    assert!((belief.mean() - 8.0 / 12.0).abs() < 1e-12);
    let summary = belief.summary().unwrap();
    assert!((summary.observations - 10.0).abs() < 1e-12);
    assert!(summary.entropy < uniform_entropy());
}

fn uniform_entropy() -> f64 {
    // Beta(1,1) has zero differential entropy; any observed posterior is sharper.
    0.0
}

#[test]
fn decision_picks_the_highest_expected_utility() {
    use organism_core::belief::{decide, Action, BetaBelief};
    let belief = BetaBelief::new(8.0, 2.0).unwrap();
    let actions = vec![
        Action {
            name: "safe".into(),
            utility_success: 1.0,
            utility_failure: 1.0,
        },
        Action {
            name: "risky".into(),
            utility_success: 10.0,
            utility_failure: -100.0,
        },
    ];
    let (best, expected) = decide(&belief, &actions).unwrap();
    assert_eq!(best, "safe");
    assert_eq!(expected.len(), 2);
}

#[test]
fn bandit_explores_then_exploits() {
    use organism_core::belief::Bandit;
    let mut bandit = Bandit::new(&["good".to_string(), "bad".to_string()]).unwrap();
    for _ in 0..200 {
        let index = bandit.select().unwrap();
        let reward = if index == 0 { 1.0 } else { 0.0 };
        bandit.update(index, reward).unwrap();
    }
    let arms = bandit.arms();
    assert!(arms[0].pulls > arms[1].pulls, "{:?}", arms);
    assert!(bandit.update(5, 0.5).is_err());
    assert!(bandit.update(0, 1.5).is_err());
}

// ---- rpc for the new modules ----

#[test]
fn rpc_memory_session_flow() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    let init = session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "memory.init",
        "params": {"capacity": 8}
    }));
    assert_eq!(init["result"]["capacity"], 8);

    let inserted = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "memory.insert",
        "params": {"content": "mkutano", "embedding": [1.0, 0.0], "now_ms": 1000, "salience": 0.9}
    }));
    assert_eq!(inserted["result"]["id"], 1);

    let found = session.handle(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "memory.search",
        "params": {"embedding": [1.0, 0.0], "limit": 1, "now_ms": 2000}
    }));
    assert_eq!(found["result"][0]["id"], 1);
    assert!(found["result"][0]["score"].as_f64().unwrap() > 0.0);

    let stats = session.handle(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "memory.stats", "params": {}
    }));
    assert_eq!(stats["result"]["live"], 1);
}

#[test]
fn rpc_memory_requires_initialisation() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    let response = session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "memory.stats", "params": {}
    }));
    assert_eq!(response["error"]["code"], -32602);
}

#[test]
fn rpc_control_and_belief_round_trip() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    let signals = session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "control.signals",
        "params": {"homes": [{"name": "energy", "target": 0.8, "current": 0.2, "tolerance": 0.2, "weight": 2.0}]}
    }));
    assert_eq!(signals["result"]["dominant"]["name"], "energy");

    let belief = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "belief.update",
        "params": {"alpha": 1, "beta": 1, "success_count": 3, "failure_count": 1}
    }));
    assert!((belief["result"]["mean"].as_f64().unwrap() - 4.0 / 6.0).abs() < 1e-12);
    assert!(belief["result"]["log_likelihood"].as_f64().unwrap() < 0.0);
}

#[test]
fn rpc_bandit_selects_unvisited_first() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "bandit.init", "params": {"arms": ["a", "b"]}
    }));
    let first = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "bandit.select", "params": {}
    }));
    assert_eq!(first["result"]["index"], 0);
    session.handle(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "bandit.update", "params": {"index": 0, "reward": 1.0}
    }));
    let second = session.handle(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "bandit.select", "params": {}
    }));
    assert_eq!(second["result"]["index"], 1);
}


// ---- guard: circuit breaker ----

#[test]
fn breaker_trips_after_the_threshold_and_recovers() {
    use organism_core::guard::{BreakerState, CircuitBreaker};
    let mut breaker = CircuitBreaker::new(2, 1_000, 2).unwrap();
    assert!(breaker.allow(0));
    breaker.record(false, 0);
    assert!(breaker.allow(0));
    breaker.record(false, 0);
    assert_eq!(breaker.status(0).state, BreakerState::Open);
    assert!(!breaker.allow(500), "still inside the cooldown");
    assert!(breaker.allow(1_000), "cooldown elapsed, half-open probe allowed");
    assert_eq!(breaker.status(1_000).state, BreakerState::HalfOpen);
    breaker.record(true, 1_000);
    breaker.record(true, 1_001);
    assert_eq!(breaker.status(1_001).state, BreakerState::Closed);
    assert_eq!(breaker.status(1_001).failures, 0);
}

#[test]
fn breaker_reopens_when_the_half_open_probe_fails() {
    use organism_core::guard::{BreakerState, CircuitBreaker};
    let mut breaker = CircuitBreaker::new(1, 100, 1).unwrap();
    breaker.record(false, 0);
    assert!(breaker.allow(100));
    breaker.record(false, 100);
    assert_eq!(breaker.status(100).state, BreakerState::Open);
    assert!(!breaker.allow(150));
}

#[test]
fn breaker_rejects_impossible_configuration() {
    use organism_core::guard::CircuitBreaker;
    assert!(CircuitBreaker::new(0, 100, 1).is_err());
    assert!(CircuitBreaker::new(1, 0, 1).is_err());
    assert!(CircuitBreaker::new(1, 100, 0).is_err());
}

// ---- guard: rate limiter ----

#[test]
fn rate_limiter_allows_a_burst_then_refills() {
    use organism_core::guard::RateLimiter;
    let mut limiter = RateLimiter::new(10.0, 5.0, 0).unwrap();
    let first = limiter.try_acquire(10.0, 0).unwrap();
    assert!(first.allowed);
    assert_eq!(first.tokens, 0.0);
    assert!(!limiter.try_acquire(1.0, 0).unwrap().allowed);
    let refilled = limiter.try_acquire(1.0, 200).unwrap();
    assert!(refilled.allowed, "5 tokens per second is 1 token per 200 ms");
}

#[test]
fn rate_limiter_refuses_a_backwards_clock() {
    use organism_core::guard::RateLimiter;
    let mut limiter = RateLimiter::new(5.0, 1.0, 1_000).unwrap();
    assert!(limiter.try_acquire(1.0, 999).is_err());
}

#[test]
fn rate_limiter_refuses_impossible_requests() {
    use organism_core::guard::RateLimiter;
    let mut limiter = RateLimiter::new(5.0, 1.0, 0).unwrap();
    assert!(limiter.try_acquire(6.0, 0).is_err(), "cost above capacity can never pass");
    assert!(limiter.try_acquire(0.0, 0).is_err());
    assert!(RateLimiter::new(0.0, 1.0, 0).is_err());
    assert!(RateLimiter::new(1.0, -1.0, 0).is_err());
    assert!(RateLimiter::new(f64::INFINITY, 1.0, 0).is_err());
}

// ---- guard over rpc ----

#[test]
fn rpc_breaker_round_trip() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "guard.breaker.init",
        "params": {"failure_threshold": 1, "cooldown_ms": 1000, "half_open_successes": 1}
    }));
    let allowed = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "guard.breaker.allow", "params": {"now_ms": 0}
    }));
    assert_eq!(allowed["result"]["allowed"], true);

    let tripped = session.handle(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "guard.breaker.record",
        "params": {"success": false, "now_ms": 0}
    }));
    assert_eq!(tripped["result"]["state"], "open");

    let blocked = session.handle(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "guard.breaker.allow", "params": {"now_ms": 10}
    }));
    assert_eq!(blocked["result"]["allowed"], false);

    let probe = session.handle(&json!({
        "jsonrpc": "2.0", "id": 5, "method": "guard.breaker.allow", "params": {"now_ms": 1000}
    }));
    assert_eq!(probe["result"]["allowed"], true);
}

#[test]
fn rpc_rate_limiter_round_trip() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "guard.rate.init",
        "params": {"capacity": 2, "refill_per_second": 1, "now_ms": 0}
    }));
    let first = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "guard.rate.acquire", "params": {"cost": 2, "now_ms": 0}
    }));
    assert_eq!(first["result"]["allowed"], true);
    let denied = session.handle(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "guard.rate.acquire", "params": {"cost": 1, "now_ms": 0}
    }));
    assert_eq!(denied["result"]["allowed"], false);
    let refilled = session.handle(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "guard.rate.acquire", "params": {"cost": 1, "now_ms": 1000}
    }));
    assert_eq!(refilled["result"]["allowed"], true);
}

#[test]
fn rpc_guard_requires_initialisation() {
    use organism_core::rpc::Session;
    let mut session = Session::new();
    let breaker = session.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "guard.breaker.status", "params": {"now_ms": 0}
    }));
    assert_eq!(breaker["error"]["code"], -32602);
    let limiter = session.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "guard.rate.status", "params": {}
    }));
    assert_eq!(limiter["error"]["code"], -32602);
}

// ---- memory persistence primitives ----

#[test]
fn memory_snapshot_round_trips_through_restore() {
    use organism_core::memory::MemoryStore;
    let mut store = MemoryStore::new(8, 0.0, 0.05).unwrap();
    let id = store.insert("a", vec![1.0, 0.0], 0, 0.8, 0.2).unwrap();
    let items = store.snapshot();
    let mut fresh = MemoryStore::new(8, 0.0, 0.05).unwrap();
    fresh.restore(items).unwrap();
    assert_eq!(fresh.stats().live, 1);
    let next = fresh.insert("b", vec![0.0, 1.0], 1, 0.5, 0.0).unwrap();
    assert_eq!(next, id + 1, "restore must continue the id sequence");
}

#[test]
fn memory_restore_refuses_bad_items() {
    use organism_core::memory::{MemoryItem, MemoryStore};
    let mut store = MemoryStore::new(2, 0.0, 0.05).unwrap();
    let item = MemoryItem {
        id: 1,
        content: "x".into(),
        embedding: vec![1.0],
        created_ms: 0,
        last_access_ms: 0,
        access_count: 0,
        salience: 0.5,
        emotion: 0.0,
        suppressed: false,
        tombstone: false,
    };
    assert!(store.restore(vec![item.clone(), item.clone()]).is_err(), "duplicate ids");
    let mut bad = item.clone();
    bad.salience = 2.0;
    assert!(store.restore(vec![bad]).is_err(), "out-of-range salience");
    let mut empty = item.clone();
    empty.content = "  ".into();
    assert!(store.restore(vec![empty]).is_err(), "empty content");
    let three = vec![item.clone(), MemoryItem { id: 2, ..item.clone() }, MemoryItem { id: 3, ..item }];
    assert!(store.restore(three).is_err(), "over capacity");
}

#[test]
fn rpc_memory_snapshot_and_restore() {
    use organism_core::rpc::Session;
    let mut first = Session::new();
    first.handle(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "memory.init", "params": {"capacity": 8}
    }));
    first.handle(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "memory.insert",
        "params": {"content": "mkutano", "embedding": [1.0], "now_ms": 10, "salience": 0.9}
    }));
    let snapshot = first.handle(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "memory.snapshot", "params": {}
    }));
    let items = snapshot["result"]["items"].clone();
    assert_eq!(items.as_array().unwrap().len(), 1);

    let mut second = Session::new();
    second.handle(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "memory.init", "params": {"capacity": 8}
    }));
    let restored = second.handle(&json!({
        "jsonrpc": "2.0", "id": 5, "method": "memory.restore", "params": {"items": items}
    }));
    assert_eq!(restored["result"]["restored"], 1);
    let found = second.handle(&json!({
        "jsonrpc": "2.0", "id": 6, "method": "memory.search",
        "params": {"embedding": [1.0], "limit": 1, "now_ms": 20}
    }));
    assert_eq!(found["result"][0]["id"], 1);
}
