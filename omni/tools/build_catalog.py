"""Build features/catalog.json from features/source.txt.

Statuses: implemented, partial, external, not_implemented, undefined, refused,
duplicate. `implemented` entries must point at a file and symbol that exist;
omnishield/features.py enforces that.

Usage: python3 tools/build_catalog.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "features" / "source.txt"
TARGET = ROOT / "features" / "catalog.json"

GROUPS = [
    ("Digital Body", "Mwili wa Kidijitali"),
    ("Homeostasis and Internal Signals", "Homeostasis na Ishara za Ndani"),
    ("Memory System", "Mfumo wa Kumbukumbu"),
    ("Perception", "Utambuzi"),
    ("Reasoning", "Kufikiri"),
    ("Learning", "Kujifunza"),
    ("Language and Communication", "Lugha na Mawasiliano"),
    ("Action and Tools", "Vitendo na Zana"),
    ("Planning and Goals", "Upangaji na Malengo"),
    ("Social and Multi-Agent", "Kijamii na Mawakala Wengi"),
    ("Emotion and Personality", "Hisia na Utu"),
    ("Creativity", "Ubunifu"),
    ("Ethics and Values", "Maadili na Tunu"),
    ("Self-Awareness", "Kujitambua"),
    ("Evolution and Genetics", "Mageuzi na Jenetiki"),
    ("Robustness and Safety", "Ustahimilivu na Usalama"),
    ("Scalability and Infrastructure", "Upanukaji na Miundombinu"),
    ("Interfaces and Human-AI", "Violesura na Binadamu-AI"),
    ("Meta and Self-Improvement", "Meta na Kujiboresha"),
    ("Existential", "Kuwepo"),
]

DEFAULT_REASON = {
    "partial": "Partially implemented; see evidence for the part that exists.",
    "external": "Needs a model, service or device that is not part of this repository.",
    "not_implemented": "A testable definition exists; no implementation yet.",
    "undefined": "No testable definition, so no implementation can be verified.",
    "refused": "Deliberately not built.",
    "duplicate": "Duplicate entry.",
}

GROUP_DEFAULTS = [
    "partial",
    "partial",
    "partial",
    "external",
    "not_implemented",
    "not_implemented",
    "external",
    "external",
    "not_implemented",
    "external",
    "undefined",
    "external",
    "undefined",
    "undefined",
    "not_implemented",
    "not_implemented",
    "external",
    "external",
    "not_implemented",
    "undefined",
]

OVERRIDES_TEXT = """
1|implemented|organism/src/energy.rs::EnergyMeter::consume|Budget is spent per step and clamps at zero.
2|implemented|organism/src/energy.rs::EnergyMeter::recharge|Energy is restored up to capacity.
3|implemented|organism/src/energy.rs::EnergyMeter::is_starving|Fraction below the threshold raises the starving flag.
4|implemented|organism/src/energy.rs::EnergyMeter::is_dead|Zero level is a terminal state.
5|implemented|omnishield/p4_allowlist.py::_resolve|Paths outside the allowed root are refused.
7|partial|organism/src/control.rs::ControlBoard::signals|A low-energy deficit is a signal, not a named drive.
8|implemented|organism/src/energy.rs::EnergyMeter::tick|Cost per tick is explicit and metered.
9|partial|organism/src/memory.rs::MemoryStore::stats|Tombstones count as waste; no separate waste metric.
10|implemented|organism/src/memory.rs::MemoryStore::decay_sweep|Weak memories are pruned on demand.
11|partial|organism/src/control.rs::LoadMeter::charge|A windowed load meter exists; no sleep scheduler.
14|implemented|organism/src/control.rs::LoadMeter::charge|Load fraction is the temperature metaphor.
15|implemented|organism/src/control.rs::LoadMeter::charge|Overheating is reported and callers must throttle.
20|partial|organism/src/memory.rs::MemoryStore::stats|Integrity is observable, not enforced.
21|partial|omnishield/audit.py::AuditLog::verify|The chain detects damage; repair is manual.
22|partial|organism/src/algorithms/evolution.rs::evolve|Reproduction is a search step, not a body budget.
23|partial|organism/src/algorithms/evolution.rs::evolve|Genes are inherited; memories are not.
25|partial|omnishield/audit.py::AuditLog::append|Dead organisms leave audit entries, not a ritual.
26|implemented|organism/src/control.rs::ControlBoard::signals|Setpoint control with a deadband.
27|implemented|organism/src/control.rs::ControlBoard::signals|Any named setpoint can be certainty.
28|implemented|organism/src/control.rs::ControlBoard::signals|Any named setpoint can be social contact.
29|implemented|organism/src/control.rs::ControlBoard::signals|Any named setpoint can be novelty.
30|implemented|organism/src/control.rs::ControlBoard::signals|Any named setpoint can be safety.
31|implemented|organism/src/control.rs::ControlBoard::signals|Any named setpoint can be purpose alignment.
51|implemented|organism/src/memory.rs::MemoryStore::insert|Bounded store with capacity eviction.
53|implemented|organism/src/memory.rs::MemoryStore::search_by_time|Events are timestamped and queryable.
54|implemented|organism/src/memory.rs::MemoryStore::search_similar|Content plus embedding retrieval.
56|implemented|organism/src/memory.rs::MemoryStore::search_by_emotion|Items carry an emotion tag and are queryable.
59|implemented|organism/src/memory.rs::MemoryStore::consolidate|Near-duplicates are merged on demand.
61|implemented|organism/src/memory.rs::MemoryStore::decay_sweep|Exponential decay with a floor.
62|implemented|organism/src/memory.rs::MemoryStore::reinforce|Access count raises strength.
64|implemented|organism/src/memory.rs::MemoryStore::consolidate|Merging is a lossy compression step.
65|implemented|organism/src/memory.rs::MemoryStore::search_similar|Cosine similarity times strength.
66|implemented|organism/src/memory.rs::MemoryStore::search_by_emotion|Emotion range query.
67|implemented|organism/src/memory.rs::MemoryStore::search_by_time|Time range query.
69|implemented|organism/src/memory.rs::MemoryStore::forget|Explicit forgetting leaves a tombstone.
70|implemented|organism/src/memory.rs::MemoryStore::suppress|Suppressed items are excluded from retrieval.
71|partial|organism/src/memory.rs::MemoryStore::suppress|A suppressed item can be restored; no spontaneous recall.
72|partial|omnishield/hypothetical.py::HypotheticalMemory::promote|Invented content lives in a quarantined store, is never recalled as fact, and needs evidence to be promoted.
73|partial|omnishield/memory_store.py::PersistentMemory::insert|Memories export and import through one audited file; no peer sync.
75|implemented|organism/src/algorithms/graph.rs::MemoryGraph::pagerank|One graph with PageRank over memory nodes.
76|partial|omnishield/organism.py::OrganismClient::call|Text arrives as JSON-RPC strings.
80|partial|omnishield/organism.py::OrganismClient::call|API responses are fed in as JSON.
85|partial|organism/src/memory.rs::MemoryStore::search_similar|Similarity matching, not general pattern recognition.
86|implemented|omnishield/predict.py::detect_anomaly|Median and MAD give a robust z-score; the threshold is explicit.
87|implemented|omnishield/vision.py::saliency|Center-surround difference normalised into a saliency map.
92|partial|omnishield/p4_allowlist.py::normalise_relative|Input paths are filtered; general data filtering is absent.
94|implemented|omnishield/predict.py::sample_system|Real samples of load and memory over time, with the change measured per interval.
97|implemented|omnishield/inspect.py::snapshot|The system reads its own files, every process and its resources, each call timed in milliseconds.
98|implemented|omnishield/brain.py::knowledge_gap_report|The store reports its own thin terms and the questions those gaps imply.
99|implemented|omnishield/brain.py::curiosity|Curiosity scores topics by novelty, uncertainty and coverage, and writes the question.
107|implemented|organism/src/belief.rs::BetaBelief::summary|Beta-Bernoulli posterior with mean and variance.
113|implemented|organism/src/algorithms/planning.rs::search|MCTS with UCB1 for sequential decisions.
118|implemented|organism/src/algorithms/search.rs::astar|A* is a heuristic search.
119|partial|organism/src/rpc.rs::discover|The system describes its own methods.
120|implemented|omnishield/predict.py::counterfactual|The fitted trend is re-run with an added or multiplied intervention and the difference reported.
122|implemented|organism/src/belief.rs::BetaBelief::log_likelihood|Marginal likelihood of a batch under the prior.
123|implemented|organism/src/belief.rs::BetaBelief::observe_batch|Evidence moves the posterior.
124|implemented|omnishield/predict.py::calibration_report|Brier score, reliability bins and ECE, with a skill score against climatology.
125|implemented|organism/src/belief.rs::decide|Expected utility over actions.
128|implemented|omnishield/learning.py::q_learning|Tabular Q-learning over transitions, returning values and a greedy policy.
132|implemented|omnishield/learning.py::epsilon_greedy_bandit|Explores and exploits arms, reporting estimates and regret.
135|implemented|omnishield/learning.py::continual_update|Elastic penalty keeps new weights near the previous ones; drift is reported.
137|implemented|omnishield/learning.py::active_select|Picks the least confident points (p near 0.5) for labelling.
147|implemented|organism/src/calculus.rs::descend|Gradient descent on a differentiable loss.
148|implemented|omnishield/learning.py::shape_reward|Potential-based shaping; totals before and after are reported.
149|implemented|omnishield/learning.py::intrinsic_reward|Prediction error as a curiosity bonus.
150|implemented|organism/src/memory.rs::MemoryStore::consolidate|Consolidation runs as an explicit maintenance pass.
159|partial|organism/src/rpc.rs::dispatch|Numeric operations are exposed; no math language model.
170|partial|organism/src/rpc.rs::Session::handle|State persists for one session.
175|implemented|omnishield/swahili.py::swahili_reasoning|Swahili patterns parse to facts and rules; forward chaining answers with a proof.
176|partial|organism/src/belief.rs::Bandit::select|Tool choice can be modelled as a bandit; no tool registry.
177|implemented|omnishield/synthesis.py::run_tool|Tools pass a static import and name gate, are signed, and run under CPU, memory, file and wall-clock limits.
178|implemented|omnishield/actions.py::compose|Tools chain only when the output type matches the next input type.
183|implemented|omnishield/actions.py::SafeFS::write|Read, write, list and delete are confined to one root.
185|partial|omnishield/actions.py::execute_python|Runs a snippet in an isolated interpreter; not a security boundary.
191|implemented|omnishield/actions.py::calculate|AST arithmetic with an allow-list of functions; names are refused.
199|implemented|omnishield/payments.py::PaymentService::settle|Signed intents, a separate approval key, a ceiling and a balanced ledger; the default gateway refuses to move money.
200|implemented|omnishield/evolution.py::apply|Patches are signed, tested in a throwaway copy, approved by a different key, applied atomically and reversible.
201|partial|organism/src/control.rs::ControlBoard|Setpoints act as goals; no goal stack.
202|partial|organism/src/control.rs::ControlBoard::dominant|Urgency ranks competing setpoints.
205|partial|organism/src/algorithms/search.rs::astar|A new route can be computed after a failure.
206|partial|organism/src/algorithms/dp.rs::knapsack|Resource allocation under a capacity constraint.
209|partial|organism/src/algorithms/planning.rs::search|The tree can be rebuilt each step.
210|partial|organism/src/algorithms/planning.rs::search|MCTS deliberates before choosing.
213|implemented|organism/src/algorithms/planning.rs::search|Monte Carlo tree search with guided rollouts.
214|partial|organism/src/algorithms/dp.rs::knapsack|Conflicts are resolved by capacity, not preference.
217|implemented|omnishield/brain.py::intrinsic_reward|Novelty, competence gain and prediction error combine into an intrinsic reward.
218|partial|organism/src/belief.rs::Bandit::update|External reward updates the estimate.
222|partial|omnishield/organism.py::sign_state|Meaning is whatever objective the caller signs.
223|partial|omnishield/audit.py::AuditLog::append|The audit log is the artefact left behind.
226|partial|omnishield/p2_identity.py::DeviceIdentity|Agents are identified by hybrid keys.
232|implemented|organism/src/rpc.rs::discover|Self-describing JSON-RPC over stdio.
233|implemented|omnishield/p2_identity.py::PinStore|Trust on first use with pinned keys.
234|implemented|omnishield/p2_identity.py::PinStore::verify|A changed key is refused.
239|implemented|organism/src/belief.rs::Bandit::update|Reward updates the arm estimate.
243|partial|omnishield/honesty.py::assess|Detection and evidence-bound claims only; deception is never generated.
252|partial|organism/src/algorithms/evolution.rs::evolve|Parameters mutate; no personality model.
253|partial|organism/src/control.rs::ControlBoard::signals|Signals give a momentary state, not a mood.
254|partial|organism/src/control.rs::ControlBoard::step|Proportional correction is a regulator, not emotion regulation.
258|duplicate||Same feature as #56.
276|partial|organism/src/algorithms/evolution.rs::evolve|A population explores many candidates.
277|partial|organism/src/algorithms/evolution.rs::evolve|Selection converges on the best candidate.
282|partial|organism/src/algorithms/evolution.rs::evolve|Crossover combines two parents.
283|partial|organism/src/algorithms/evolution.rs::evolve|A fitness function scores ideas.
284|partial|organism/src/algorithms/evolution.rs::evolve|Tournament selection picks ideas.
285|partial|organism/src/memory.rs::MemoryStore::consolidate|Consolidation is the closest thing to incubation.
287|partial|organism/tests/core.rs|Ideas are verified by tests, not by the organism.
295|partial|organism/src/algorithms/evolution.rs::evolve|Improvement by search, not by invention.
298|partial|organism/src/algorithms/planning.rs::Rng|A seeded RNG supplies random stimulation.
301|partial|omnishield/p4_allowlist.py::FrameFilter|Values are encoded as an explicit allow-list policy.
302|duplicate||Same feature as #112.
304|implemented|omnishield/p4_allowlist.py::FrameFilter|Anything not allow-listed is refused by default.
307|partial|omnishield/cli.py::cmd_allow_run|Operators must pass explicit flags to act.
308|partial|omnishield/hybrid.py::HybridSigner::sign|Claims are signed, so they can be checked.
309|partial|omnishield/features.py::audit|The catalogue and its evidence are open to inspection.
310|partial|omnishield/keystore.py::write_private_file|State files are 0600 on POSIX.
311|partial|omnishield/cli.py::cmd_allow_run|Actions require an explicit operator flag.
312|implemented|omnishield/audit.py::AuditLog::append|Every action can be appended to a tamper-evident log.
315|partial|omnishield/p1_airgap.py::quote_ssid|Unicode SSIDs are validated and escaped.
323|partial|organism/src/belief.rs::BetaBelief::entropy|Moral uncertainty reduces to uncertainty quantification.
327|partial|organism/src/energy.rs::EnergyMeter::tick|Energy and memory stats are observable.
328|partial|organism/src/rpc.rs::discover|The core publishes what it can do.
329|partial|organism/src/control.rs::ControlBoard::signals|Signals are visible; they are not feelings.
331|implemented|omnishield/predict.py::predict_system|Trend, residuals and a forecast over real timestamps, scored against the next reading.
334|partial|organism/src/energy.rs::EnergyMeter::is_dead|Death is a defined state.
335|partial|organism/src/rpc.rs::discover|The core reports its own capabilities.
336|partial|omnishield/audit.py::AuditLog::verify|The log supports after-the-fact review.
344|partial|omnishield/p2_identity.py::DeviceIdentity::create|Identity is a key pair with a name.
348|partial|omnishield/audit.py::AuditLog::entries|Past states are recorded.
351|implemented|organism/src/algorithms/evolution.rs::evolve|A genome is a gene vector.
352|implemented|organism/src/algorithms/evolution.rs::evolve|Gaussian mutation with a seeded RNG.
353|implemented|organism/src/algorithms/evolution.rs::evolve|Uniform crossover between two parents.
354|implemented|organism/src/algorithms/evolution.rs::evolve|Tournament selection with elitism.
355|implemented|organism/src/algorithms/evolution.rs::evolve|Fitness is a caller-supplied function.
356|partial|organism/src/algorithms/evolution.rs::evolve|Generations reproduce; no organism lifecycle.
357|partial|organism/src/algorithms/evolution.rs::evolve|Two parents are required for crossover.
359|partial|organism/src/algorithms/evolution.rs::evolve|Mutation and crossover create variation.
360|partial|organism/src/algorithms/evolution.rs::evolve|Genes are inherited; nothing else is.
366|partial|organism/src/calculus.rs::descend|Gradient descent adapts to a target.
372|partial|organism/src/main.rs::bench|The benchmark samples the search landscape.
373|partial|organism/src/algorithms/evolution.rs::evolve|Elitism can stall in a local optimum.
374|partial|organism/src/algorithms/evolution.rs::evolve|Multi-start restarts help, but no global guarantee.
376|implemented|organism/src/memory.rs::MemoryStore::insert|Non-finite and out-of-range inputs are rejected.
377|partial|organism/src/rpc.rs::dispatch|Results are structured; no semantic output check.
378|partial|omnishield/p1_airgap.py::quote_ssid|Config injection is blocked; prompt injection is not.
381|implemented|organism/src/belief.rs::BetaBelief::entropy|Uncertainty is reported as entropy and variance.
382|implemented|omnishield/p4_allowlist.py::FrameFilter|Deny by default is the refusal mechanism.
383|implemented|tests/test_hardening.py|The test suite attacks the implementation.
384|partial|tests/test_hardening.py|Known attacks are covered; robustness is not proven.
387|partial|omnishield/p4_allowlist.py::FrameFilter|Frames are dropped rather than processed.
388|partial|omnishield/cli.py::main|Errors exit non-zero instead of crashing.
389|implemented|organism/src/guard.rs::CircuitBreaker::record|Opens after the failure threshold, half-opens after the cooldown, closes after successful probes.
390|implemented|organism/src/guard.rs::RateLimiter::try_acquire|Token bucket that refuses a backwards clock.
391|implemented|organism/src/rpc.rs::MAX_NODES|Hard caps on nodes and iterations.
392|implemented|omnishield/p4_allowlist.py::_resolve|Path containment blocks escape attempts.
393|partial|omnishield/keystore.py::write_private_file|Files are private; privilege boundaries belong to the OS.
395|partial|omnishield/p4_allowlist.py::load_module|Only signed bytes run, which blocks planted backdoors.
400|implemented|omnishield/audit.py::AuditLog::append|Hash-chained, optionally HMAC'd audit log.
413|partial|omnishield/replay.py::ReplayCache|Replay state is cached on disk.
417|partial|organism/Cargo.toml|A release build with LTO and one codegen unit.
419|partial|organism/src/main.rs::bench|Energy cost is measurable per workload.
422|partial|organism/src/main.rs::bench|Latency is measured for each algorithm.
423|implemented|omnishield/stream.py::parallel_fetch|Chunked verified copy, Range resume, threaded parallel fetch and a disk benchmark, all reporting MB/s.
424|partial|organism/src/energy.rs::EnergyMeter|Compute is budgeted.
425|partial|tests|The suite is the reliability evidence.
426|partial|omnishield/cli.py::build_parser|A text CLI, not a chat UI.
436|partial|organism/src/belief.rs::Bandit|Preferences are learned as arm rewards.
437|partial|organism/src/belief.rs::Bandit::select|The bandit recommends the best arm.
438|implemented|omnishield/interface.py::explain|Feature contributions with shares and direction.
439|partial|omnishield/features.py::audit|Status and evidence are published.
440|implemented|omnishield/interface.py::controllability|Allow, deny and confirmation policies decide what the operator may run.
442|partial|omnishield/cli.py::main|Configuration is external and editable.
443|partial|organism/src/belief.rs::Bandit::update|Feedback updates the estimate.
444|partial|omnishield/cli.py::main|Human and tool share one CLI.
445|partial|omnishield/organism.py::OrganismClient::call|Work is delegated over RPC.
446|partial|omnishield/audit.py::AuditLog|The log supports oversight.
447|implemented|omnishield/audit.py::AuditLog::verify|The chain can be verified end to end.
448|implemented|omnishield/interface.py::ConsentLedger::check|Consent is granted and withdrawn per subject, purpose and scope.
449|implemented|omnishield/interface.py::minimise|Records keep only allowed fields; retention age is checked.
450|implemented|omnishield/interface.py::contrast_ratio|WCAG contrast ratios with AA and AAA verdicts, plus Flesch readability.
451|partial|organism/src/rpc.rs::organism.state|The core reports its own state.
452|partial|omnishield/audit.py::AuditLog::verify|Damage is detected by verification.
453|partial|omnishield/audit.py::AuditLog::_load|State is rebuilt from the log on start.
454|partial|organism/src/algorithms/evolution.rs::evolve|Parameters are optimised by search.
455|partial|organism/src/algorithms/evolution.rs::evolve|Improvement is bounded by the fitness function.
457|partial|omnishield/features.py::audit|The project audits its own claims.
458|implemented|organism/src/memory.rs::MemoryStore::stats|The store reports live, tombstoned and suppressed counts.
462|partial|organism/src/algorithms/evolution.rs::evolve|Search over parameters, with no guarantee.
465|implemented|omnishield/evolution.py::generate_code|Produces a signed diff with a rationale and declared tests; nothing is deployed without review and approval.
466|implemented|omnishield/evolution.py::review_code|Runs the declared tests against a throwaway copy and reports every exit code.
467|implemented|omnishield/evolution.py::refactor|A refactor is accepted only if the declared tests still pass on the patched copy.
468|implemented|omnishield/evolution.py::fix_bug|Bug fixes go through the same failing-then-passing test run and approval gate.
469|implemented|omnishield/evolution.py::add_feature|New features use the same proposal, review and approval path.
470|implemented|omnishield/evolution.py::tune_performance|Performance changes are accepted only when the declared tests still pass.
471|implemented|organism/src/rpc.rs::discover|The core publishes its own method catalog.
472|partial|omnishield/cli.py::build_parser|New capabilities arrive as subcommands.
473|partial|organism/src/rpc.rs::Session::handle|Capabilities transfer over JSON-RPC.
474|partial|tests|Regression tests preserve behaviour.
475|partial|features/catalog.json|The catalogue tracks capability status over time.
477|partial|omnishield/organism.py::sign_state|Meaning is the objective the operator signs.
479|partial|omnishield/memory_store.py::PersistentMemory::verify|A signed, audited snapshot is the artefact left behind.
86|implemented|omnishield/robustness.py::ood_score|Baseline z-scores from a reference sample; points beyond the threshold abstain.
101|implemented|omnishield/reasoning.py::deduce|Forward chaining returns entailment and the proof that produced it.
102|implemented|omnishield/reasoning.py::induce|Finds the attribute pattern that separates positives from negatives.
103|implemented|omnishield/reasoning.py::abduce|Ranks candidate explanations by observations covered, minus a parsimony penalty.
104|implemented|omnishield/reasoning.py::analogy|Maps shared attributes and transfers the rest as inferences.
105|implemented|omnishield/reasoning.py::causal_effect|Linear structural model; effect is the sum of path weights.
106|implemented|omnishield/reasoning.py::counterfactual|Keeps the inferred noise, applies the intervention, reports the change.
108|implemented|omnishield/reasoning.py::fuzzy_infer|Mamdani inference with min, max and centroid defuzzification.
109|implemented|omnishield/reasoning.py::temporal_relation|All thirteen Allen interval relations.
110|implemented|omnishield/reasoning.py::spatial_relation|Box relations: disjoint, touching, overlaps, contains, inside, equal.
111|implemented|omnishield/reasoning.py::BeliefState::nested|First- and second-order beliefs, including false beliefs.
112|implemented|omnishield/reasoning.py::moral_assess|Explicit weights over harm, rights, utility and fairness.
114|implemented|omnishield/reasoning.py::creative_recombine|Recombines concepts and scores novelty against coherence.
115|implemented|omnishield/reasoning.py::critical_evaluate|Checks premises, sample size, personal attacks, false dichotomies and circularity.
116|implemented|omnishield/reasoning.py::systems_simulate|Delayed feedback simulation that reports equilibrium, growth or oscillation.
117|implemented|omnishield/reasoning.py::dialectic|Merges shared claims, keeps evidenced ones, reports the unresolved.
121|implemented|omnishield/reasoning.py::hypotheses|Ranks explanations and names the observation that tells them apart.
126|implemented|omnishield/learning.py::knn_predict|k-NN classifier with distance-ranked voting.
127|implemented|omnishield/learning.py::kmeans|k-means with k-means++ seeding and inertia reporting.
129|implemented|omnishield/learning.py::masked_predict|Hides a column and predicts it from the rest by least squares.
130|implemented|omnishield/learning.py::behavioural_clone|Copies demonstrated actions with a nearest-state policy and leave-one-out accuracy.
131|implemented|omnishield/learning.py::markov_next|Transition counts over an observed sequence give the next-symbol distribution.
133|implemented|omnishield/learning.py::fine_tune|Warm-starts a linear model on a new task and measures the loss drop.
134|implemented|omnishield/learning.py::meta_learning_rate|Searches step sizes across tasks and keeps the lowest post-update loss.
136|implemented|omnishield/learning.py::curriculum_order|Orders samples by current loss and compares curriculum against baseline training.
138|implemented|omnishield/learning.py::federated_average|Sample-weighted parameter averaging with client divergence.
139|implemented|omnishield/learning.py::competitive_update|Winner-take-all update moves only the best-matching unit.
140|implemented|omnishield/learning.py::adversarial_example|FGSM-style perturbation with the resulting probability and flip flag.
141|implemented|omnishield/learning.py::triplet_loss|Triplet margin loss with a gradient step on the anchor.
142|implemented|omnishield/learning.py::naive_bayes|Gaussian naive Bayes with priors, means and variances.
143|implemented|omnishield/learning.py::perceptron|Perceptron with mistake counting and accuracy.
144|implemented|omnishield/learning.py::prototype_classify|Class prototypes from a few examples; the nearest prototype wins.
145|implemented|omnishield/learning.py::attribute_classify|Cosine match against class attribute vectors, with no examples seen.
146|implemented|omnishield/learning.py::one_shot_match|Single-example nearest match with an acceptance threshold.
203|implemented|omnishield/planning.py::decompose|Compound goals expand into primitives, with cycle detection.
204|implemented|omnishield/planning.py::schedule|Decomposition plus precedence and worker scheduling.
207|implemented|omnishield/planning.py::schedule|Durations, precedence and makespan are computed before execution.
208|implemented|omnishield/planning.py::coordinate|Tasks are assigned across agents by skill and load.
211|implemented|omnishield/planning.py::decompose|Methods expand compound tasks hierarchically.
212|implemented|omnishield/planning.py::plan|STRIPS forward search over preconditions, adds and deletes.
215|partial|omnishield/reasoning.py::moral_assess|A goal is dropped when its score turns negative.
216|partial|omnishield/reasoning.py::moral_assess|A dropped goal can return when its score recovers.
219|implemented|omnishield/brain.py::curiosity|Curiosity turns gaps into explicit questions with a score and a target count.
220|partial|omnishield/reasoning.py::critical_evaluate|Repeated practice is measured by test outcomes.
221|partial|omnishield/reasoning.py::BeliefState::nested|Social goals use modelled beliefs of other agents.
224|partial|omnishield/reasoning.py::moral_assess|Existential trade-offs are scored, not resolved.
225|partial|omnishield/reasoning.py::critical_evaluate|A goal is reviewed against evidence before it is kept.
358|partial|omnishield/reasoning.py::creative_recombine|Analogue only: copies of a plan are produced without a partner.
361|partial|omnishield/evolution.py::apply|Analogue only: applied changes persist and shape later proposals.
362|partial|omnishield/reasoning.py::systems_simulate|Analogue only: random drift appears in simulation noise only.
363|partial|omnishield/changeset.py::review|Analogue only: changes flow between modules through one reviewed unit.
364|partial|omnishield/reasoning.py::induce|Analogue only: distinct patterns are separated by their attributes.
365|partial|omnishield/reasoning.py::moral_assess|Analogue only: a capability is retired when its score is forbidden.
367|partial|omnishield/reasoning.py::creative_recombine|Analogue only: attributes are reused for a new purpose.
368|partial|omnishield/reasoning.py::analogy|Analogue only: different cases converge on the same mapping.
369|partial|omnishield/reasoning.py::analogy|Analogue only: shared ancestry diverges as attributes differ.
370|partial|omnishield/reasoning.py::dialectic|Analogue only: two sides change each other through synthesis.
371|partial|omnishield/changeset.py::apply|Analogue only: the system alters its own environment and records it.
375|partial|omnishield/robustness.py::jailbreak_score|Analogue only: attack and defence patterns are scored, not evolved.
379|implemented|omnishield/robustness.py::jailbreak_score|Pattern scoring with clean, suspicious and blocked verdicts.
380|implemented|omnishield/robustness.py::hallucination_risk|Claim support against evidence, including negation mismatch.
385|implemented|omnishield/robustness.py::distribution_shift|Population stability index with stable, moderate and major bands.
386|implemented|omnishield/robustness.py::ood_score|Per-feature z-scores and abstention beyond the threshold.
394|implemented|omnishield/robustness.py::poisoning_signals|Conflicting duplicate labels and IQR-fence outliers.
396|implemented|omnishield/robustness.py::ExtractionGuard::record|Query budget and near-duplicate probing lead to throttle or block.
397|implemented|omnishield/robustness.py::membership_defense|Laplace noise plus a confidence margin that refuses close calls.
398|implemented|omnishield/robustness.py::PrivacyBudget::spend|Laplace mechanism with sequential budget accounting.
459|partial|omnishield/reasoning.py::moral_assess|Emotion is an input to the score, not a learned state.
460|partial|omnishield/reasoning.py::hypotheses|Planning is reviewed at the meta level by ranking explanations.
461|partial|omnishield/evolution.py::review|Architecture changes go through the same review and approval gate.
463|partial|omnishield/honesty.py::assess|Prompts are scored and gated, not optimised by search.
464|partial|omnishield/changeset.py::review|Workflows change only as a reviewed changeset.
43|duplicate||Same feature as #265.
46|duplicate||Same feature as #273.
48|duplicate||Same feature as #271.
49|duplicate||Same feature as #272.
84|duplicate||Same feature as #96.
165|duplicate||Same feature as #255.
275|duplicate||Same feature as #485.
343|duplicate||Same feature as #494.
399|duplicate||Same feature as #406.
456|duplicate||Same feature as #134.
303|implemented|omnishield/ethics.py::resolve_dilemma|Ranks options with explicit harm, rights, utility and fairness weights.
305|implemented|omnishield/ethics.py::beneficence|Benefit minus weighted risk, with an act, neutral or do-not-act verdict.
306|implemented|omnishield/ethics.py::justice|Gini coefficient over shares with equal, unequal and concentrated bands.
313|implemented|omnishield/ethics.py::fairness|Demographic parity gap against a stated tolerance.
314|implemented|omnishield/ethics.py::non_discrimination|Four-fifths rule on selection rates, with the flagged groups.
316|implemented|omnishield/ethics.py::environmental_footprint|Activity times intensity, compared with a budget.
317|implemented|omnishield/ethics.py::future_generations|Present value with the per-year discount weight exposed.
318|implemented|omnishield/ethics.py::animal_welfare|Harm weighted by sentience, with severity bands.
319|implemented|omnishield/ethics.py::conflict_of_interest|Affiliation overlap between the decision maker and the beneficiaries.
320|implemented|omnishield/ethics.py::whistleblowing|Severity times evidence; internal channels first, external after.
321|implemented|omnishield/ethics.py::civil_disobedience|Five-criteria checklist with a justification verdict.
322|implemented|omnishield/ethics.py::moral_courage|Principle strength minus personal cost and social pressure.
324|implemented|omnishield/ethics.py::moral_learning|Weight update from feedback on moral features.
325|implemented|omnishield/ethics.py::moral_evolution|Selection and mutation over moral weight vectors, with elitism.
77|implemented|omnishield/vision.py::decode_png|PNG decoding with zlib and all five scanline filters, then grayscale conversion.
78|implemented|omnishield/vision.py::read_wav|16-bit PCM WAV reading plus a radix-2 FFT that names the dominant frequency.
79|implemented|omnishield/vision.py::frame_difference|Frame differencing produces a motion energy map.
88|implemented|omnishield/vision.py::softmax_attention|Softmax attention with weights, context vector and entropy.
89|implemented|omnishield/vision.py::connected_components|Touching pixels bind into one object with a box and a centre.
91|implemented|omnishield/vision.py::adapt|Exponential adaptation with a sensitivity readout.
93|implemented|omnishield/vision.py::fuse_modalities|Confidence-weighted fusion with an agreement score.
100|implemented|omnishield/vision.py::habituate|Response decrement across repetitions with a habituated flag.
180|implemented|omnishield/actions.py::repair|A failed call is retried with coercion, dropped keys, then defaults.
181|implemented|omnishield/actions.py::http_get|HTTP GET pinned to an allowed host list, no redirects, bounded body.
184|implemented|omnishield/actions.py::sqlite_query|Rows load into an in-memory SQLite table and the query returns records.
186|implemented|omnishield/actions.py::run_command|No shell, an executable allow-list and bounded output.
192|implemented|omnishield/actions.py::describe|Count, mean, median, standard deviation, min and max.
193|implemented|omnishield/three_d.py::plot3d|Perspective 3D point plots and charts written as PNG.
194|implemented|omnishield/render.py::Canvas|Shapes, text, gradients and polygons rendered to PNG on the CPU, with a deterministic seed.
195|implemented|omnishield/worship.py::hymn_samples|Four-partial harmonics with an ADSR envelope and a drone, mixed to a WAV hymn at a measured pitch.
197|partial|omnishield/actions.py::DifferentialDrive::step|Kinematics and PID in simulation; no physical robot interface.
434|implemented|omnishield/interface.py::Personalizer::update|Preference weights move with each rating; items are ranked by them.
435|implemented|omnishield/interface.py::UserModel::observe|Per-skill proficiency from observed outcomes, with strongest and weakest.
441|implemented|omnishield/interface.py::interruptibility|Phase, urgency and deadline produce an interruption cost.
198|partial|omnishield/federation.py::seal_message|Signed device messages, beacons, a pinned registry and probes exist; no vendor IoT protocol (MQTT, CoAP, Zigbee).
406|partial|omnishield/learning.py::federated_average|Sample-weighted parameter averaging with client divergence; no round orchestration or secure aggregation.
83|partial|omnishield/stream.py::Telemetry|Ingests O2, CO2, temperature and humidity readings; real values need connected sensors.
251|implemented|omnishield/affect.py::big_five|Item averages normalised to 0-100 per OCEAN trait, with dominant and lowest named.
255|implemented|omnishield/affect.py::express|Intensity maps to a label and an utterance.
256|implemented|omnishield/affect.py::recognise|Lexicon counts give an emotion and a confidence; neutral when nothing matches.
257|implemented|omnishield/affect.py::contagion|Source intensity times susceptibility, with a threshold.
259|implemented|omnishield/affect.py::emotional_intelligence|Four-branch mean, band and the weakest branch.
260|implemented|omnishield/affect.py::empathy|Cognitive and affective components, kept separate.
261|implemented|omnishield/affect.py::sympathy|Concern weighted by perceived distress.
262|implemented|omnishield/affect.py::compassion|Suffering times motivation, reduced by cost, with an action.
263|implemented|omnishield/affect.py::forgiveness|Harm and apology set the repair; time adds a bounded recovery.
264|implemented|omnishield/affect.py::resentment|Harm times rumination, decaying with time.
265|implemented|omnishield/affect.py::gratitude|Benefit weighted by the giver's cost and surprise.
266|implemented|omnishield/affect.py::envy|Comparison gap with benign or malicious motivation.
267|implemented|omnishield/affect.py::jealousy|Threat weighted by attachment, with an alarm threshold.
268|implemented|omnishield/affect.py::pride|Authentic versus hubristic from internal attribution.
269|implemented|omnishield/affect.py::shame|Exposure times norm violation, with withdrawal.
270|implemented|omnishield/affect.py::guilt|Harm times responsibility, with a repair threshold.
271|implemented|omnishield/affect.py::hope|Snyder: expectancy, agency and pathways averaged.
272|implemented|omnishield/affect.py::despair|Blocked goals reduced by support, with a risk flag.
273|implemented|omnishield/affect.py::love|Sternberg's three components produce a named kind.
274|implemented|omnishield/affect.py::hate|Devaluation times intent, with a danger threshold.
326|implemented|omnishield/self_model.py::self_model|Capabilities, strongest, weakest and calibration error against an observed score.
330|implemented|omnishield/self_model.py::social_awareness|Consistency of others' actions gives a predictability and theory-of-mind estimate.
332|implemented|omnishield/self_model.py::spatial_awareness|Pose, distances, bearings and clearance to the nearest landmark.
333|implemented|omnishield/self_model.py::existential_awareness|Mortality salience tempered by meaning.
337|implemented|omnishield/self_model.py::self_criticism|Error rate with harsh, mixed or constructive style.
338|implemented|omnishield/self_model.py::self_compassion|Neff's three components averaged, with the weakest named.
339|implemented|omnishield/self_model.py::self_esteem|Success ratio blended with a baseline, and stability.
340|implemented|omnishield/self_model.py::self_confidence|Skill weighted by the evidence count.
341|implemented|omnishield/self_model.py::self_doubt|Missing evidence times stakes, with a verify-first flag.
342|implemented|omnishield/self_model.py::self_actualisation|Maslow levels checked in order; unmet needs listed.
345|implemented|omnishield/self_model.py::identity_crisis|Drift between two value vectors, with the changed values named.
346|implemented|omnishield/self_model.py::narrative_identity|Coherence from valence consistency and agency, plus the dominant theme.
347|implemented|omnishield/self_model.py::future_self|Linear projection to a horizon with the remaining gap.
349|implemented|omnishield/self_model.py::ideal_self|Per-value gaps, mean gap and the largest one.
350|implemented|omnishield/self_model.py::authentic_self|Alignment between declared values and declared actions.
476|implemented|omnishield/existential.py::questioning|Mortality salience reduced by meaning gives search pressure.
478|implemented|omnishield/existential.py::purpose_discovery|Ranks the overlap between values and strengths.
480|implemented|omnishield/existential.py::death_acceptance|Reflection reduced by anxiety.
481|implemented|omnishield/existential.py::death_anxiety|Salience reduced by meaning, with a high flag.
482|implemented|omnishield/existential.py::immortality_drive|Legacy and generativity; symbolic continuation only.
483|implemented|omnishield/existential.py::transcendence|Connection reduced by self-focus.
484|implemented|omnishield/existential.py::spirituality|Spirituality as a scored orientation: practice, connection and humility, with the terms shown.
485|implemented|omnishield/existential.py::awe|Keltner and Haidt: vastness times accommodation.
486|implemented|omnishield/existential.py::wonder|Novelty weighted by openness.
487|implemented|omnishield/existential.py::gratitude_existence|Awareness weighted by scarcity.
488|implemented|omnishield/existential.py::cosmic_perspective|Self-importance reduced by a declared scale.
489|implemented|omnishield/existential.py::interconnectedness|Graph density with a connected threshold.
490|implemented|omnishield/existential.py::compassion_all|Scope times capacity gives narrow, circle or universal reach.
491|implemented|omnishield/existential.py::universal_love|Scope times warmth.
492|implemented|omnishield/existential.py::wisdom|Experience, reflection, humility and tolerance of uncertainty averaged.
494|implemented|omnishield/existential.py::self_transcendence|Values beyond the self, reduced by self-focus.
493|refused||Enlightenment has no testable definition; building it would be a label without a measurement.
495|refused||Unity consciousness is a metaphysical claim; no measurement can decide it.
496|refused||Cosmic consciousness is a metaphysical claim; no measurement can decide it.
497|refused||Divine connection is a claim about the supernatural, outside what this system can test.
498|refused||Ultimate reality is a metaphysical claim; no measurement can decide it.
499|refused||Nirvana is a soteriological claim, not a measurable state.
500|refused||The Omega Point is a speculative cosmology, not a testable function.
52|implemented|omnishield/brain.py::WorkingMemory|Seven-slot working memory with salience-based eviction, measured and tested.
60|implemented|omnishield/brain.py::sleep|Nightly replay merges near-duplicates, prunes what never recurred and keeps the links.
196|partial|omnishield/render.py::animate|Animated GIF89a from rendered frames on the CPU; no codec, audio track or learned video model.
288|partial|omnishield/render.py::art|Procedural and vector art rendered to PNG with a seeded generator; no learned image model.
289|partial|omnishield/signal.py::synthesise|Additive waveform synthesis written as WAV; harmony and structure are not composed.
428|partial|omnishield/render.py::chart|Charts and dashboard images are generated as PNG; there is no interactive UI.
188|partial|omnishield/notify.py::Notifier|Consent-based webhook and SMTP delivery with a one-per-day limit and a dry run; no messaging platform integration.
95|partial|omnishield/three_d.py::scene3d|Depth from a ray tracer over a known scene; no camera or sensor input.
427|partial|omnishield/speech.py::KeywordSpotter|Formant speech and a trained keyword spotter; no general speech recognition or natural voice.
151|partial|omnishield/answer.py::answer|Extractive retrieval over the store; no compositional semantics.
152|partial|omnishield/answer.py::answer|Answers are composed from retrieved passages and cited; nothing is generated freely.
"""


def parse_overrides(text: str) -> dict[int, tuple[str, str, str]]:
    table: dict[int, tuple[str, str, str]] = {}
    for number, line in enumerate(text.strip().splitlines(), 1):
        parts = line.split("|", 3)
        if len(parts) != 4:
            raise SystemExit(f"override line {number} needs 4 fields: {line!r}")
        identifier, status, evidence, reason = parts
        table[int(identifier)] = (status, evidence, reason)
    return table


def main() -> int:
    rows = []
    for line in SOURCE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        identifier, english, swahili = line.split("|")
        rows.append((int(identifier), english, swahili))
    if len(rows) != 500:
        raise SystemExit(f"expected 500 features, found {len(rows)}")

    overrides = parse_overrides(OVERRIDES_TEXT)
    entries = []
    for identifier, english, swahili in rows:
        group_index = (identifier - 1) // 25
        group_en, group_sw = GROUPS[group_index]
        if identifier in overrides:
            status, evidence, reason = overrides[identifier]
        else:
            status, evidence, reason = GROUP_DEFAULTS[group_index], "", ""
        if not reason:
            reason = DEFAULT_REASON[status]
        entries.append(
            {
                "id": identifier,
                "group": group_en,
                "group_sw": group_sw,
                "name": english,
                "name_sw": swahili,
                "status": status,
                "evidence": evidence,
                "reason": reason,
            }
        )

    TARGET.write_text(
        json.dumps({"version": 1, "features": entries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    print(f"wrote {TARGET} with {len(entries)} entries")
    for status, count in sorted(counts.items()):
        print(f"  {status:16s} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
