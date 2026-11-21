//! `organism` binary: JSON-RPC server, single call, discovery, demo.

use std::io::{self, BufRead, Write};

use organism_core::algorithms::dp::knapsack;
use organism_core::algorithms::evolution::{evolve, GaConfig};
use organism_core::algorithms::graph::MemoryGraph;
use organism_core::algorithms::planning::{search as mcts_search, LineGame};
use organism_core::algorithms::search::{astar, Edge};
use organism_core::calculus::{descend, Quadratic};
use organism_core::energy::EnergyMeter;
use organism_core::render::render_to_ppm;
use organism_core::pathtrace::render_json_to_ppm;
use organism_core::neuron::{bench as neuron_bench, forward, parse_list, train_step};
use organism_core::render3d::render3d_to_ppm;
use organism_core::rpc;
use serde_json::{json, Value};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("rpc") {
        "rpc" => serve(),
        "discover" => print_pretty(&rpc::discover()),
        "call" => {
            let method = args.get(2).cloned().unwrap_or_default();
            let params: Value = args
                .get(3)
                .map(|raw| serde_json::from_str(raw).unwrap_or(Value::Null))
                .unwrap_or_else(|| json!({}));
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let mut session = rpc::Session::new();
            let response = session.handle(&request);
            print_pretty(&response);
            if response.get("error").is_some() {
                std::process::exit(2);
            }
        }
        "pathtrace" => {
            let scene_path = args.get(2).cloned().unwrap_or_else(|| "scene.json".to_string());
            let out = args.get(3).cloned().unwrap_or_else(|| "pathtrace.ppm".to_string());
            let text = match std::fs::read_to_string(&scene_path) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("cannot read {scene_path}: {error}");
                    std::process::exit(1);
                }
            };
            match render_json_to_ppm(&text) {
                Ok((ppm, elapsed_ms, pixels, threads, bounces)) => match std::fs::write(&out, &ppm) {
                    Ok(()) => print_pretty(&json!({
                        "path": out,
                        "bytes": ppm.len(),
                        "pixels": pixels,
                        "threads": threads,
                        "bounces": bounces,
                        "elapsed_ms": (elapsed_ms * 1000.0).round() / 1000.0,
                        "pixels_per_second": ((pixels as f64) / (elapsed_ms / 1000.0)).round(),
                    })),
                    Err(error) => {
                        eprintln!("cannot write {out}: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("bad scene: {error}");
                    std::process::exit(2);
                }
            }
        }
        "neuron" => {
            let mode = args.get(2).map(String::as_str).unwrap_or("forward");
            match mode {
                "forward" => {
                    let inputs = match parse_list(args.get(3).map(String::as_str).unwrap_or("")) {
                        Ok(values) => values,
                        Err(error) => {
                            eprintln!("bad inputs: {error}");
                            std::process::exit(2);
                        }
                    };
                    let weights = match parse_list(args.get(4).map(String::as_str).unwrap_or("")) {
                        Ok(values) => values,
                        Err(error) => {
                            eprintln!("bad weights: {error}");
                            std::process::exit(2);
                        }
                    };
                    let bias: f64 = args.get(5).and_then(|text| text.parse().ok()).unwrap_or(0.0);
                    match forward(&inputs, &weights, bias) {
                        Ok(prediction) => print_pretty(&json!({
                            "inputs": inputs.len(),
                            "weights": weights.len(),
                            "bias": bias,
                            "dot": inputs.iter().zip(&weights).map(|(x, w)| x * w).sum::<f64>(),
                            "prediction": prediction,
                        })),
                        Err(error) => {
                            eprintln!("{error}");
                            std::process::exit(2);
                        }
                    }
                }
                "bench" => {
                    let dimension: usize = args.get(3).and_then(|text| text.parse().ok()).unwrap_or(20_000);
                    let repeats: usize = args.get(4).and_then(|text| text.parse().ok()).unwrap_or(10);
                    match neuron_bench(dimension, repeats) {
                        Ok((ms, total, elapsed)) => print_pretty(&json!({
                            "dimension": dimension,
                            "repeats": repeats,
                            "ms_per_dot": (ms * 1000.0).round() / 1000.0,
                            "total": total,
                            "seconds": (elapsed * 1000.0).round() / 1000.0,
                        })),
                        Err(error) => {
                            eprintln!("{error}");
                            std::process::exit(2);
                        }
                    }
                }
                "train" => {
                    let inputs = parse_list(args.get(3).map(String::as_str).unwrap_or("")).unwrap_or_default();
                    let weights = parse_list(args.get(4).map(String::as_str).unwrap_or("")).unwrap_or_default();
                    let bias: f64 = args.get(5).and_then(|text| text.parse().ok()).unwrap_or(0.0);
                    let target: f64 = args.get(6).and_then(|text| text.parse().ok()).unwrap_or(1.0);
                    let rate: f64 = args.get(7).and_then(|text| text.parse().ok()).unwrap_or(0.5);
                    match train_step(&inputs, &weights, bias, target, rate) {
                        Ok((next, next_bias, before, loss)) => print_pretty(&json!({
                            "prediction_before": before,
                            "weights_after": next,
                            "bias_after": next_bias,
                            "loss": loss,
                        })),
                        Err(error) => {
                            eprintln!("{error}");
                            std::process::exit(2);
                        }
                    }
                }
                other => {
                    eprintln!("unknown neuron mode {other}");
                    std::process::exit(2);
                }
            }
        }
        "render3d" => {
            let width = args.get(2).and_then(|value| value.parse().ok()).unwrap_or(320);
            let height = args.get(3).and_then(|value| value.parse().ok()).unwrap_or(200);
            let samples = args.get(4).and_then(|value| value.parse().ok()).unwrap_or(1);
            let out = args.get(5).cloned().unwrap_or_else(|| "scene3d.ppm".to_string());
            let threads = args.get(6).and_then(|value| value.parse().ok()).unwrap_or(1);
            let angle = args.get(7).and_then(|value| value.parse().ok()).unwrap_or(0.0);
            let aperture = args.get(8).and_then(|value| value.parse().ok()).unwrap_or(0.0);
            let (ppm, elapsed_ms, rays) = render3d_to_ppm(width, height, samples, threads, angle, aperture);
            match std::fs::write(&out, &ppm) {
                Ok(()) => print_pretty(&json!({
                    "path": out,
                    "bytes": ppm.len(),
                    "width": width,
                    "height": height,
                    "samples": samples,
                    "threads": threads,
                    "angle": angle,
                    "aperture": aperture,
                    "rays": rays,
                    "elapsed_ms": (elapsed_ms * 1000.0).round() / 1000.0,
                    "rays_per_second": ((rays as f64) / (elapsed_ms / 1000.0)).round(),
                })),
                Err(error) => {
                    eprintln!("cannot write {out}: {error}");
                    std::process::exit(1);
                }
            }
        }
        "render" => {
            let width = args.get(2).and_then(|value| value.parse().ok()).unwrap_or(480);
            let height = args.get(3).and_then(|value| value.parse().ok()).unwrap_or(300);
            let samples = args.get(4).and_then(|value| value.parse().ok()).unwrap_or(2);
            let out = args.get(5).cloned().unwrap_or_else(|| "scene.ppm".to_string());
            let (ppm, elapsed_ms, pixels) = render_to_ppm(width, height, samples);
            match std::fs::write(&out, &ppm) {
                Ok(()) => print_pretty(&json!({
                    "path": out,
                    "bytes": ppm.len(),
                    "width": width,
                    "height": height,
                    "samples": samples,
                    "elapsed_ms": (elapsed_ms * 1000.0).round() / 1000.0,
                    "pixels_per_second": ((pixels as f64) / (elapsed_ms / 1000.0)).round(),
                })),
                Err(error) => {
                    eprintln!("cannot write {out}: {error}");
                    std::process::exit(1);
                }
            }
        }
        "demo" => demo(),
        "bench" => bench(),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: organism [rpc|discover|call <method> <json>|render <w> <h> <samples> <out>|render3d <w> <h> <samples> <out>|neuron forward <x> <w> <b>|pathtrace <scene.json> <out>|demo|bench]");
            std::process::exit(2);
        }
    }
}

fn print_pretty(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("serialisation error: {error}"),
    }
}

fn serve() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut session = rpc::Session::new();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("stdin error: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => session.handle(&request),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": format!("parse error: {error}")}
            }),
        };
        if writeln!(out, "{response}").is_err() {
            break;
        }
        if out.flush().is_err() {
            break;
        }
    }
}

fn bench() {
    use organism_core::algorithms::planning::Rng;
    use std::time::Instant;

    let mut report = json!({"organism": "bench"});

    // A* on a 100x100 grid with diagonal moves.
    let side = 100usize;
    let index = |x: usize, y: usize| y * side + x;
    let neighbors = |node: usize| {
        let x = node % side;
        let y = node / side;
        let mut edges = Vec::with_capacity(8);
        for (dx, dy, cost) in [
            (1usize, 0usize, 1.0),
            (0, 1, 1.0),
            (1, 1, 1.5),
        ] {
            if x + dx < side && y + dy < side {
                edges.push(Edge {
                    to: index(x + dx, y + dy),
                    cost,
                });
            }
        }
        edges
    };
    let heuristic = |node: usize| {
        let x = (node % side) as f64;
        let y = (node / side) as f64;
        (side as f64 - 1.0 - x) + (side as f64 - 1.0 - y)
    };
    let rounds = 20u32;
    let started = Instant::now();
    let mut expanded = 0usize;
    for _ in 0..rounds {
        let found = astar(side * side, 0, side * side - 1, neighbors, heuristic)
            .expect("valid grid")
            .expect("path exists");
        expanded = found.expanded;
    }
    let per_run = started.elapsed().as_secs_f64() * 1000.0 / rounds as f64;
    report["astar"] = json!({
        "grid": format!("{side}x{side}"),
        "nodes": side * side,
        "ms_per_search": per_run,
        "expanded": expanded,
    });

    // PageRank over 10,000 nodes.
    let nodes = 10_000usize;
    let mut graph = MemoryGraph::new();
    for index in 0..nodes {
        graph.add_node(format!("m{index}"));
    }
    let mut rng = Rng::new(99);
    for index in 0..nodes {
        graph.add_edge(index, (index + 1) % nodes, 1.0).expect("valid edge");
        for _ in 0..3 {
            let target = rng.next_range(nodes);
            graph.add_edge(index, target, 1.0).expect("valid edge");
        }
    }
    let started = Instant::now();
    let scores = graph.pagerank(0.85, 50, 1e-10).expect("converges");
    report["pagerank"] = json!({
        "nodes": nodes,
        "iterations": 50,
        "ms": started.elapsed().as_secs_f64() * 1000.0,
        "total": scores.iter().sum::<f64>(),
    });

    // MCTS throughput.
    let game = LineGame::new(50).expect("valid game");
    let iterations = 100_000u32;
    let started = Instant::now();
    let plan = mcts_search(&game, iterations, 48, 3).expect("valid search");
    let elapsed = started.elapsed().as_secs_f64();
    report["mcts"] = json!({
        "iterations": iterations,
        "iterations_per_second": iterations as f64 / elapsed,
        "best_action": plan.best_action,
    });

    // Genetic algorithm.
    let target: Vec<f64> = (0..50).map(|index| (index as f64 / 50.0) - 0.5).collect();
    let config = GaConfig {
        population: 200,
        generations: 200,
        mutation_rate: 0.1,
        crossover_rate: 0.5,
        elite: 10,
        seed: 4,
    };
    let started = Instant::now();
    let evolution = evolve(&target, &config, |genes| {
        -genes
            .iter()
            .zip(&target)
            .map(|(gene, want)| (gene - want).powi(2))
            .sum::<f64>()
    })
    .expect("valid evolution");
    report["ga"] = json!({
        "population": config.population,
        "generations": config.generations,
        "genes": target.len(),
        "ms": started.elapsed().as_secs_f64() * 1000.0,
        "best_distance": (-evolution.best.fitness).max(0.0),
    });

    // Knapsack.
    let mut rng = Rng::new(5);
    let weights: Vec<u64> = (0..200).map(|_| 1 + rng.next_range(500) as u64).collect();
    let values: Vec<u64> = (0..200).map(|_| 1 + rng.next_range(1000) as u64).collect();
    let started = Instant::now();
    let packed = knapsack(&weights, &values, 50_000).expect("valid knapsack");
    report["knapsack"] = json!({
        "items": weights.len(),
        "capacity": 50_000,
        "ms": started.elapsed().as_secs_f64() * 1000.0,
        "best_value": packed.best_value,
    });

    print_pretty(&report);
}

fn demo() {
    let mut report = json!({"organism": "demo"});

    let mut meter = EnergyMeter::new(100.0, 0.2).expect("valid meter");
    let ticks: Vec<Value> = (0..5)
        .map(|step| {
            let cost = 18.0 + step as f64;
            let tick = meter.tick(cost, 10.0).expect("valid tick");
            json!(tick)
        })
        .collect();
    report["energy"] = json!(ticks);

    let objective = Quadratic::new(0.8, 1.0).expect("valid objective");
    let trajectory = descend(&objective, 0.0, 0.2, 60).expect("converges");
    report["homeostasis"] = json!({
        "final": trajectory.xs.last().copied().unwrap_or(0.0),
        "loss": trajectory.losses.last().copied().unwrap_or(0.0),
        "steps": trajectory.xs.len() - 1,
    });

    let side = 4usize;
    let index = |x: usize, y: usize| y * side + x;
    let neighbors = |node: usize| {
        let x = node % side;
        let y = node / side;
        let mut edges = Vec::new();
        if x + 1 < side {
            edges.push(Edge {
                to: index(x + 1, y),
                cost: 1.0,
            });
        }
        if y + 1 < side {
            edges.push(Edge {
                to: index(x, y + 1),
                cost: 1.0,
            });
        }
        if x + 1 < side && y + 1 < side {
            edges.push(Edge {
                to: index(x + 1, y + 1),
                cost: 1.5,
            });
        }
        edges
    };
    let goal_x = side - 1;
    let goal_y = side - 1;
    let heuristic = |node: usize| {
        let x = (node % side) as f64;
        let y = (node / side) as f64;
        (goal_x as f64 - x).abs() + (goal_y as f64 - y).abs()
    };
    let route = astar(side * side, 0, side * side - 1, neighbors, heuristic).expect("valid search");
    report["search"] = json!(route);

    let mut graph = MemoryGraph::new();
    let ids: Vec<usize> = ["root", "docs", "code", "tests", "index"]
        .iter()
        .map(|label| graph.add_node(*label))
        .collect();
    for (from, to) in [(0, 1), (1, 2), (2, 3), (3, 0), (1, 4), (4, 2)] {
        graph.add_edge(ids[from], ids[to], 1.0).expect("valid edge");
    }
    let scores = graph.pagerank(0.85, 100, 1e-10).expect("converges");
    report["memory"] = json!({
        "top": graph.ranked(&scores, 3),
        "total": scores.iter().sum::<f64>(),
    });

    let game = LineGame::new(12).expect("valid game");
    let plan = mcts_search(&game, 3000, 24, 7).expect("valid search");
    report["planning"] = json!(plan);

    let target = [0.4, -0.2, 0.9];
    let config = GaConfig {
        population: 80,
        generations: 120,
        mutation_rate: 0.2,
        crossover_rate: 0.5,
        elite: 4,
        seed: 11,
    };
    let evolution = evolve(&target, &config, |genes| {
        -genes
            .iter()
            .zip(&target)
            .map(|(gene, want)| (gene - want).powi(2))
            .sum::<f64>()
    })
    .expect("valid evolution");
    report["evolution"] = json!({
        "best_genes": evolution.best.genes,
        "best_distance": (-evolution.best.fitness).max(0.0),
    });

    let packed = knapsack(&[12, 7, 11, 8, 9], &[24, 13, 23, 15, 16], 26).expect("valid knapsack");
    report["knapsack"] = json!(packed);

    print_pretty(&report);
}
