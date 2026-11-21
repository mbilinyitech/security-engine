//! Genetic algorithm with tournament selection, uniform crossover, elitism.

use serde::Serialize;

use super::planning::Rng;

#[derive(Debug, Clone, Serialize)]
pub struct Individual {
    pub genes: Vec<f64>,
    pub fitness: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct GaConfig {
    pub population: usize,
    pub generations: usize,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub elite: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionReport {
    pub best: Individual,
    pub best_history: Vec<f64>,
}

impl GaConfig {
    pub fn validate(&self, target: &[f64]) -> Result<(), String> {
        if target.is_empty() {
            return Err("target must not be empty".into());
        }
        if target.iter().any(|value| !value.is_finite()) {
            return Err("target genes must be finite".into());
        }
        if self.population < 4 || self.population > 10_000 {
            return Err("population must be in [4, 10000]".into());
        }
        if self.generations == 0 || self.generations > 100_000 {
            return Err("generations must be in [1, 100000]".into());
        }
        if !(0.0..=1.0).contains(&self.mutation_rate) {
            return Err("mutation_rate must be in [0, 1]".into());
        }
        if !(0.0..=1.0).contains(&self.crossover_rate) {
            return Err("crossover_rate must be in [0, 1]".into());
        }
        if self.elite > self.population / 2 {
            return Err("elite must not exceed half the population".into());
        }
        Ok(())
    }
}

fn gaussian(rng: &mut Rng) -> f64 {
    let u1 = rng.next_f64().max(1e-12);
    let u2 = rng.next_f64();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

pub fn evolve<F>(target: &[f64], cfg: &GaConfig, fitness: F) -> Result<EvolutionReport, String>
where
    F: Fn(&[f64]) -> f64,
{
    cfg.validate(target)?;
    let mut rng = Rng::new(cfg.seed);
    let mut population: Vec<Individual> = (0..cfg.population)
        .map(|_| Individual {
            genes: (0..target.len()).map(|_| rng.next_f64() * 2.0 - 1.0).collect(),
            fitness: 0.0,
        })
        .collect();

    let mut best_history = Vec::with_capacity(cfg.generations);
    let mut best = population[0].clone();

    for _ in 0..cfg.generations {
        for individual in population.iter_mut() {
            individual.fitness = fitness(&individual.genes);
        }
        population.sort_by(|a, b| b.fitness.total_cmp(&a.fitness));
        if population[0].fitness > best.fitness {
            best = population[0].clone();
        }
        best_history.push(population[0].fitness);

        let mut next: Vec<Individual> = population[..cfg.elite].to_vec();
        while next.len() < cfg.population {
            let parent_a = tournament(&population, &mut rng);
            let parent_b = tournament(&population, &mut rng);
            let mut genes = Vec::with_capacity(target.len());
            for (a, b) in parent_a.genes.iter().zip(&parent_b.genes) {
                genes.push(if rng.next_f64() < cfg.crossover_rate {
                    *a
                } else {
                    *b
                });
            }
            for gene in genes.iter_mut() {
                if rng.next_f64() < cfg.mutation_rate {
                    *gene += gaussian(&mut rng) * 0.2;
                }
            }
            next.push(Individual {
                genes,
                fitness: 0.0,
            });
        }
        population = next;
    }

    Ok(EvolutionReport {
        best,
        best_history,
    })
}

fn tournament(population: &[Individual], rng: &mut Rng) -> Individual {
    let mut best = &population[rng.next_range(population.len())];
    for _ in 0..2 {
        let candidate = &population[rng.next_range(population.len())];
        if candidate.fitness > best.fitness {
            best = candidate;
        }
    }
    best.clone()
}
