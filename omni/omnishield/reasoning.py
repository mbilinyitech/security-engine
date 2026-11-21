"""Reasoning engines that compute, not describe.

Every function here is a small algorithm with a defined input and a checkable
output: forward chaining with proofs, pattern induction, abductive ranking, a
linear structural causal model, Mamdani fuzzy inference, Allen interval algebra,
RCC-style box relations, second-order beliefs, weighted moral scoring,
combinatorial recombination, argument critique, delayed feedback simulation, and
dialectical merging.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

Fact = tuple[str, tuple[Any, ...]]


class ReasoningError(Exception):
    pass


def fact(name: str, *args: Any) -> Fact:
    return (name, tuple(args))


def _fmt(item: Fact) -> str:
    name, args = item
    return name if not args else f"{name}({', '.join(str(value) for value in args)})"


class KnowledgeBase:
    """Ground facts and Horn-style rules, closed by forward chaining."""

    def __init__(self) -> None:
        self.facts: set[Fact] = set()
        self.rules: list[tuple[tuple[Fact, ...], Fact]] = []

    def tell(self, item: Fact) -> KnowledgeBase:
        self.facts.add(item)
        return self

    def rule(self, premises: Iterable[Fact], conclusion: Fact) -> KnowledgeBase:
        self.rules.append((tuple(premises), conclusion))
        return self

    def closure(self, limit: int = 5000) -> set[Fact]:
        facts = set(self.facts)
        changed = True
        while changed and len(facts) < limit:
            changed = False
            for premises, conclusion in self.rules:
                if conclusion in facts:
                    continue
                if all(premise in facts for premise in premises):
                    facts.add(conclusion)
                    changed = True
        return facts


def deduce(kb: KnowledgeBase, query: Fact) -> dict[str, Any]:
    facts = set(kb.facts)
    derivations: dict[Fact, tuple[Fact, ...]] = {}
    changed = True
    while changed:
        changed = False
        for premises, conclusion in kb.rules:
            if conclusion in facts:
                continue
            if all(premise in facts for premise in premises):
                facts.add(conclusion)
                derivations[conclusion] = premises
                changed = True
    if query not in facts:
        return {"entails": False, "proof": []}
    proof: list[dict[str, Any]] = []
    frontier = [query]
    seen: set[Fact] = set()
    while frontier:
        item = frontier.pop()
        if item in seen or item not in derivations:
            continue
        seen.add(item)
        premises = derivations[item]
        proof.append(
            {"conclusion": _fmt(item), "premises": [_fmt(premise) for premise in premises]}
        )
        frontier.extend(premises)
    return {"entails": True, "proof": proof}


def induce(
    positives: Sequence[Mapping[str, Any]], negatives: Sequence[Mapping[str, Any]] = ()
) -> dict[str, Any]:
    if not positives:
        raise ReasoningError("induction needs at least one positive example")
    common = set(positives[0])
    for row in positives[1:]:
        common &= set(row)
    pattern: dict[str, Any] = {}
    for key in sorted(common):
        values = {row.get(key) for row in positives}
        if len(values) != 1:
            continue
        value = next(iter(values))
        if any(row.get(key) == value for row in negatives):
            continue
        pattern[key] = value
    if not pattern:
        raise ReasoningError("no attribute separates the positives from the negatives")
    covered = sum(
        1 for row in positives if all(row.get(k) == v for k, v in pattern.items())
    )
    return {
        "pattern": pattern,
        "support": round(covered / len(positives), 3),
        "positives": len(positives),
        "negatives": len(negatives),
    }


def abduce(
    kb: KnowledgeBase,
    observations: Iterable[Fact],
    candidates: Iterable[Fact],
    *,
    penalty: float = 0.1,
) -> list[dict[str, Any]]:
    wanted = list(observations)
    results = []
    for candidate in candidates:
        trial = KnowledgeBase()
        trial.facts = set(kb.facts) | {candidate}
        trial.rules = kb.rules
        derived = trial.closure()
        explained = [item for item in wanted if item in derived]
        results.append(
            {
                "hypothesis": _fmt(candidate),
                "explained": len(explained),
                "score": round(len(explained) - penalty, 3),
                "covers": [_fmt(item) for item in explained],
            }
        )
    results.sort(key=lambda row: (-row["score"], row["hypothesis"]))
    return results


def analogy(source: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    shared = sorted(set(source) & set(target))
    mapping = {
        key: {"source": source[key], "target": target[key], "equal": source[key] == target[key]}
        for key in shared
    }
    inferences = {
        key: source[key]
        for key in source
        if key not in target
    }
    universe = set(source) | set(target)
    return {
        "mapping": mapping,
        "inferences": inferences,
        "score": round(len(shared) / len(universe), 3) if universe else 0.0,
    }


@dataclass
class LinearSCM:
    """Linear structural causal model: each node is a weighted sum of its parents."""

    edges: dict[str, dict[str, float]] = field(default_factory=dict)

    def add(self, parent: str, child: str, weight: float) -> LinearSCM:
        self.edges.setdefault(parent, {})[child] = float(weight)
        self.edges.setdefault(child, {})
        return self

    def parents(self, node: str) -> dict[str, float]:
        return {
            parent: children[node]
            for parent, children in self.edges.items()
            if node in children
        }

    def nodes(self) -> list[str]:
        return sorted(self.edges)

    def order(self) -> list[str]:
        incoming = {node: len(self.parents(node)) for node in self.nodes()}
        ready = sorted(node for node, count in incoming.items() if count == 0)
        ordered: list[str] = []
        while ready:
            node = ready.pop(0)
            ordered.append(node)
            for child in sorted(self.edges.get(node, {})):
                incoming[child] -= 1
                if incoming[child] == 0:
                    ready.append(child)
            ready.sort()
        if len(ordered) != len(incoming):
            raise ReasoningError("the graph has a cycle")
        return ordered

    def paths(self, source: str, target: str) -> list[tuple[list[str], float]]:
        found: list[tuple[list[str], float]] = []

        def walk(node: str, trail: list[str], weight: float) -> None:
            if node == target:
                found.append((trail, weight))
                return
            for child, coefficient in self.edges.get(node, {}).items():
                if child in trail:
                    continue
                walk(child, [*trail, child], weight * coefficient)

        walk(source, [source], 1.0)
        return found

    def total_effect(self, treatment: str, outcome: str) -> float:
        return sum(weight for _, weight in self.paths(treatment, outcome))

    def evaluate(
        self, values: Mapping[str, float], interventions: Mapping[str, float] | None = None
    ) -> dict[str, float]:
        state = {node: float(values.get(node, 0.0)) for node in self.nodes()}
        fixed = dict(interventions or {})
        for node in self.order():
            if node in fixed:
                state[node] = float(fixed[node])
                continue
            parents = self.parents(node)
            if parents:
                state[node] = sum(state[parent] * weight for parent, weight in parents.items())
        return state


def causal_effect(scm: LinearSCM, treatment: str, outcome: str, *, change: float = 1.0) -> dict[str, Any]:
    routes = scm.paths(treatment, outcome)
    effect = sum(weight for _, weight in routes) * change
    return {
        "effect": round(effect, 6),
        "paths": [
            {"route": " -> ".join(route), "weight": round(weight, 6)} for route, weight in routes
        ],
    }


def counterfactual(
    scm: LinearSCM,
    observed: Mapping[str, float],
    intervention: Mapping[str, float],
    query: str,
) -> dict[str, Any]:
    """Abduction, action, prediction: keep the noise, change the mechanism."""
    base = scm.evaluate(observed)
    noise = {
        node: float(observed.get(node, 0.0)) - base.get(node, 0.0) for node in scm.nodes()
    }
    state = {node: float(observed.get(node, 0.0)) for node in scm.nodes()}
    fixed = dict(intervention)
    for node in scm.order():
        if node in fixed:
            state[node] = float(fixed[node])
            continue
        parents = scm.parents(node)
        if parents:
            state[node] = (
                sum(state[parent] * weight for parent, weight in parents.items()) + noise[node]
            )
    actual = float(observed.get(query, 0.0))
    return {
        "actual": round(actual, 6),
        "counterfactual": round(state[query], 6),
        "change": round(state[query] - actual, 6),
    }


def _membership(value: float, triangle: tuple[float, float, float]) -> float:
    left, peak, right = triangle
    if value <= left or value >= right:
        return 0.0
    if value == peak:
        return 1.0
    if value < peak:
        return (value - left) / (peak - left) if peak > left else 1.0
    return (right - value) / (right - peak) if right > peak else 1.0


def fuzzy_infer(
    rules: Sequence[tuple[Mapping[str, str], str]],
    sets: Mapping[str, tuple[float, float, float]],
    inputs: Mapping[str, float],
    *,
    universe: tuple[float, float] = (0.0, 1.0),
    steps: int = 101,
) -> dict[str, Any]:
    """Mamdani inference: min for AND, max for aggregation, centroid for output."""
    strengths: list[tuple[str, float]] = []
    for antecedent, consequent in rules:
        memberships = [
            _membership(inputs[variable], sets[term]) for variable, term in antecedent.items()
        ]
        strengths.append((consequent, min(memberships) if memberships else 0.0))
    low, high = universe
    sample = [low + (high - low) * index / (steps - 1) for index in range(steps)]
    aggregated = []
    for point in sample:
        level = 0.0
        for consequent, strength in strengths:
            level = max(level, min(strength, _membership(point, sets[consequent])))
        aggregated.append(level)
    total = sum(aggregated)
    value = sum(point * level for point, level in zip(sample, aggregated)) / total if total else 0.0
    return {
        "value": round(value, 4),
        "strengths": {name: round(strength, 4) for name, strength in strengths},
        "support": round(total / steps, 4),
    }


def temporal_relation(a: tuple[float, float], b: tuple[float, float]) -> str:
    a1, a2 = a
    b1, b2 = b
    if a1 > a2 or b1 > b2:
        raise ReasoningError("an interval must start before it ends")
    if a1 == b1 and a2 == b2:
        return "equals"
    if a2 < b1:
        return "before"
    if a2 == b1:
        return "meets"
    if a1 > b2:
        return "after"
    if a1 == b2:
        return "met_by"
    if a1 == b1:
        return "starts" if a2 < b2 else "started_by"
    if a2 == b2:
        return "finishes" if a1 > b1 else "finished_by"
    if a1 < b1 and a2 > b2:
        return "contains"
    if a1 > b1 and a2 < b2:
        return "during"
    if a1 < b1 < a2 < b2:
        return "overlaps"
    return "overlapped_by"


def spatial_relation(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> str:
    ax1, ay1, ax2, ay2 = a
    bx1, by1, bx2, by2 = b
    if (ax1, ay1, ax2, ay2) == (bx1, by1, bx2, by2):
        return "equal"
    if ax2 < bx1 or bx2 < ax1 or ay2 < by1 or by2 < ay1:
        return "disjoint"
    if ax2 == bx1 or bx2 == ax1 or ay2 == by1 or by2 == ay1:
        return "touching"
    if ax1 <= bx1 and ay1 <= by1 and ax2 >= bx2 and ay2 >= by2:
        return "contains"
    if bx1 <= ax1 and by1 <= ay1 and bx2 >= ax2 and by2 >= ay2:
        return "inside"
    return "overlaps"


class BeliefState:
    """First- and second-order beliefs: what an agent believes, and what it believes others believe."""

    def __init__(self) -> None:
        self.first: dict[str, set[str]] = {}
        self.second: dict[tuple[str, str], set[str]] = {}

    def update(self, agent: str, proposition: str, value: bool = True) -> BeliefState:
        store = self.first.setdefault(agent, set())
        store.add(proposition) if value else store.discard(proposition)
        return self

    def believes(self, agent: str, proposition: str) -> bool:
        return proposition in self.first.get(agent, set())

    def update_nested(
        self, agent: str, other: str, proposition: str, value: bool = True
    ) -> BeliefState:
        store = self.second.setdefault((agent, other), set())
        store.add(proposition) if value else store.discard(proposition)
        return self

    def nested(self, agent: str, other: str) -> list[str]:
        return sorted(self.second.get((agent, other), set()))

    def false_belief(self, agent: str, other: str) -> list[str]:
        """Propositions agent attributes to other that other does not hold."""
        return sorted(
            proposition
            for proposition in self.nested(agent, other)
            if not self.believes(other, proposition)
        )


def moral_assess(
    action: str,
    *,
    harm: float = 0.0,
    rights: float = 0.0,
    utility: float = 0.0,
    fairness: float = 0.0,
) -> dict[str, Any]:
    """Weights are explicit so the judgement can be argued with, not hidden."""
    weights = {"harm": -1.0, "rights": -1.0, "utility": 0.5, "fairness": 0.5}
    inputs = {"harm": harm, "rights": rights, "utility": utility, "fairness": fairness}
    score = sum(inputs[key] * weights[key] for key in weights)
    if score <= -2:
        verdict = "forbidden"
    elif score < 0:
        verdict = "permitted_with_conditions"
    elif score < 1:
        verdict = "permitted"
    else:
        verdict = "required"
    return {
        "action": action,
        "score": round(score, 3),
        "verdict": verdict,
        "drivers": {
            key: round(inputs[key] * weights[key], 3) for key in sorted(weights)
        },
    }


def creative_recombine(
    concepts: Mapping[str, Iterable[str]], *, limit: int = 3
) -> list[dict[str, Any]]:
    names = sorted(concepts)
    attributes = {name: set(concepts[name]) for name in names}
    candidates = []
    for i, left in enumerate(names):
        for right in names[i + 1 :]:
            union = attributes[left] | attributes[right]
            shared = attributes[left] & attributes[right]
            if not union:
                continue
            novelty = 1.0 - max(
                (len(union & other) / len(union | other)) for other in attributes.values()
            )
            coherence = len(shared) / len(union)
            candidates.append(
                {
                    "concept": f"{left}+{right}",
                    "attributes": sorted(union),
                    "novelty": round(novelty, 3),
                    "coherence": round(coherence, 3),
                    "score": round(0.6 * novelty + 0.4 * coherence, 3),
                }
            )
    candidates.sort(key=lambda row: (-row["score"], row["concept"]))
    return candidates[:limit]


def critical_evaluate(argument: Mapping[str, Any]) -> dict[str, Any]:
    premises = list(argument.get("premises", []))
    conclusion = str(argument.get("conclusion", "")).lower()
    sample = argument.get("sample")
    attacks = [str(item).lower() for item in argument.get("attacks", [])]
    fallacies: list[str] = []
    if any(not premise.get("evidence", False) for premise in premises):
        fallacies.append("unsupported_premise")
    if conclusion.startswith(("all ", "every ", "no ")) and isinstance(sample, int) and sample < 30:
        fallacies.append("hasty_generalisation")
    if any("stupid" in attack or "liar" in attack or "idiot" in attack for attack in attacks):
        fallacies.append("ad_hominem")
    if "either" in conclusion and " or " in conclusion:
        fallacies.append("false_dichotomy")
    if any(premise.get("text", "").lower().strip(".") == conclusion.strip(".") for premise in premises):
        fallacies.append("circular")
    score = max(0.0, 1.0 - 0.25 * len(fallacies))
    return {
        "score": round(score, 3),
        "verdict": "sound" if not fallacies else ("weak" if score >= 0.5 else "fallacious"),
        "fallacies": fallacies,
        "premises": len(premises),
    }


def systems_simulate(
    nodes: Mapping[str, Mapping[str, float]],
    links: Iterable[tuple[str, str, float, int]],
    *,
    steps: int = 30,
) -> dict[str, Any]:
    """Stock-flow simulation with optional link delays."""
    levels = {name: float(config.get("level", 0.0)) for name, config in nodes.items()}
    decay = {name: float(config.get("decay", 0.0)) for name, config in nodes.items()}
    history = {name: [levels[name]] for name in levels}
    prepared = [(source, target, float(gain), int(delay)) for source, target, gain, delay in links]
    for _ in range(steps):
        delta = {name: -decay[name] * levels[name] for name in levels}
        for source, target, gain, delay in prepared:
            index = len(history[source]) - 1 - max(delay, 0)
            value = history[source][max(index, 0)]
            delta[target] = delta.get(target, 0.0) + gain * value
        levels = {name: levels[name] + delta.get(name, 0.0) for name in levels}
        for name in levels:
            history[name].append(levels[name])
    final = {name: round(levels[name], 4) for name in levels}
    spans = {name: max(series) - min(series) for name, series in history.items()}
    changes = {
        name: abs(series[-1] - series[-2]) if len(series) > 1 else 0.0
        for name, series in history.items()
    }
    behaviour = "equilibrium"
    if any(change > 1e-6 for change in changes.values()):
        behaviour = "growth" if any(series[-1] > series[0] for series in history.values()) else "oscillation"
    if all(span < 1e-6 for span in spans.values()):
        behaviour = "equilibrium"
    return {
        "trajectory": {name: [round(value, 4) for value in series] for name, series in history.items()},
        "final": final,
        "behaviour": behaviour,
    }


def dialectic(thesis: Mapping[str, Any], antithesis: Mapping[str, Any]) -> dict[str, Any]:
    def claims(side: Mapping[str, Any]) -> dict[str, int]:
        return {
            str(claim["text"]).strip().lower(): int(claim.get("evidence", 0))
            for claim in side.get("claims", [])
        }

    left = claims(thesis)
    right = claims(antithesis)
    shared = sorted(set(left) & set(right))
    only_left = {text: left[text] for text in set(left) - set(right)}
    only_right = {text: right[text] for text in set(right) - set(left)}
    synthesis = list(shared)
    unresolved: list[dict[str, Any]] = []
    for text in sorted(set(only_left) | set(only_right)):
        if text in only_left:
            if left[text] > 0:
                synthesis.append(text)
            else:
                unresolved.append({"text": text, "side": "thesis", "evidence": left[text]})
        elif text in only_right:
            if right[text] > 0:
                synthesis.append(text)
            else:
                unresolved.append({"text": text, "side": "antithesis", "evidence": right[text]})
    return {
        "synthesis": sorted(set(synthesis)),
        "shared": shared,
        "unresolved": unresolved,
        "score": round(len(shared) / max(len(set(left) | set(right)), 1), 3),
    }


def hypotheses(
    kb: KnowledgeBase, observations: Iterable[Fact], candidates: Iterable[Fact]
) -> list[dict[str, Any]]:
    """Rank explanations and say which observation would tell them apart."""
    ranked = abduce(kb, observations, candidates)
    covers = {row["hypothesis"]: set(row["covers"]) for row in ranked}
    for row in ranked:
        others: set[str] = set()
        for name, covered in covers.items():
            if name != row["hypothesis"]:
                others |= covered
        row["discriminating"] = sorted(covers[row["hypothesis"]] - others)
        row["needs_test"] = not row["discriminating"] and row["explained"] > 0
    return ranked
