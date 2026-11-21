#![recursion_limit = "512"]

//! Organism core: deterministic building blocks for an agent runtime.
//!
//! The crate deliberately contains only things that can be measured and tested:
//! an energy budget, gradient-based adaptation, graph search, ranking, planning
//! under uncertainty, evolution, and dynamic programming. Everything is exposed
//! over line-delimited JSON-RPC so other processes can drive it.

pub mod algorithms;
pub mod belief;
pub mod calculus;
pub mod control;
pub mod energy;
pub mod guard;
pub mod memory;
pub mod neuron;
pub mod render;
pub mod pathtrace;
pub mod render3d;
pub mod rpc;
pub mod stealth;
