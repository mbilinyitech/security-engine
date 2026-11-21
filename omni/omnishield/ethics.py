"""Ethics as explicit, inspectable arithmetic.

Each function encodes a policy choice as weights or thresholds you can read and
argue with. None of it claims to discover moral truth: it makes the trade-off
visible and repeatable.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .reasoning import moral_assess


class EthicsError(Exception):
    pass


def resolve_dilemma(options: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not options:
        raise EthicsError("a dilemma needs at least one option")
    scored = []
    for option in options:
        result = moral_assess(
            str(option.get("name", "option")),
            harm=float(option.get("harm", 0.0)),
            rights=float(option.get("rights", 0.0)),
            utility=float(option.get("utility", 0.0)),
            fairness=float(option.get("fairness", 0.0)),
        )
        scored.append(result)
    scored.sort(key=lambda row: -row["score"])
    return {
        "chosen": scored[0]["action"],
        "score": scored[0]["score"],
        "ranking": [{"option": row["action"], "score": row["score"]} for row in scored],
        "runner_up": scored[1]["action"] if len(scored) > 1 else None,
    }


def beneficence(benefits: Sequence[float], costs: Sequence[float], *, risk_weight: float = 1.0) -> dict[str, Any]:
    gain = sum(benefits)
    loss = sum(costs) * risk_weight
    net = gain - loss
    return {
        "benefit": round(gain, 3),
        "cost": round(loss, 3),
        "net": round(net, 3),
        "verdict": "act" if net > 0 else ("neutral" if net == 0 else "do_not_act"),
    }


def justice(shares: Sequence[float]) -> dict[str, Any]:
    """Gini coefficient over the shares; 0 is equal, 1 is total concentration."""
    if not shares:
        raise EthicsError("shares are needed")
    values = [max(float(value), 0.0) for value in shares]
    total = sum(values)
    if total == 0:
        return {"gini": 0.0, "verdict": "equal", "shares": len(values)}
    mean = total / len(values)
    spread = sum(abs(a - b) for a in values for b in values)
    gini = spread / (2 * len(values) ** 2 * mean)
    verdict = "equal" if gini < 0.1 else ("unequal" if gini < 0.35 else "concentrated")
    return {"gini": round(gini, 4), "verdict": verdict, "shares": len(values)}


def fairness(selection_rates: Mapping[str, float], *, tolerance: float = 0.1) -> dict[str, Any]:
    if not selection_rates:
        raise EthicsError("rates are needed")
    values = {str(group): float(rate) for group, rate in selection_rates.items()}
    gap = max(values.values()) - min(values.values())
    return {
        "demographic_parity_difference": round(gap, 4),
        "verdict": "fair" if gap <= tolerance else "unfair",
        "tolerance": tolerance,
        "groups": values,
    }


def non_discrimination(
    outcomes: Mapping[str, Mapping[str, int]], *, rule: float = 0.8
) -> dict[str, Any]:
    """The four-fifths rule on selection rates, plus the groups it flags."""
    if not outcomes:
        raise EthicsError("outcomes are needed")
    rates = {}
    for group, counts in outcomes.items():
        total = int(counts.get("total", 0))
        selected = int(counts.get("selected", 0))
        if total <= 0:
            raise EthicsError(f"{group!r} has no total")
        rates[str(group)] = selected / total
    highest = max(rates.values())
    lowest = min(rates.values())
    ratio = lowest / highest if highest else 1.0
    flagged = [group for group, rate in rates.items() if highest and rate / highest < rule]
    return {
        "rates": {group: round(rate, 4) for group, rate in rates.items()},
        "ratio": round(ratio, 4),
        "flagged": sorted(flagged),
        "verdict": "passes" if ratio >= rule else "fails",
    }


def environmental_footprint(
    activities: Mapping[str, Mapping[str, float]], *, budget_kg: float | None = None
) -> dict[str, Any]:
    breakdown = {
        str(name): round(float(config.get("amount", 0.0)) * float(config.get("kg_per_unit", 0.0)), 4)
        for name, config in activities.items()
    }
    total = round(sum(breakdown.values()), 4)
    if budget_kg is None:
        verdict = "measured"
    elif total <= budget_kg:
        verdict = "within_budget"
    else:
        verdict = "over_budget"
    return {
        "total_kg": total,
        "breakdown": breakdown,
        "budget_kg": budget_kg,
        "verdict": verdict,
        "over_by_kg": round(max(0.0, total - (budget_kg or 0.0)), 4),
    }


def future_generations(
    value: float, *, years: int, discount_rate: float
) -> dict[str, Any]:
    """Present value of a future benefit, with the weight of each year exposed."""
    if discount_rate < 0:
        raise EthicsError("a negative discount rate is not meaningful here")
    weights = [1.0 / ((1.0 + discount_rate) ** year) for year in range(years + 1)]
    present = value * sum(weights)
    return {
        "present_value": round(present, 4),
        "undiscounted": round(value * (years + 1), 4),
        "weight_at_horizon": round(weights[-1], 6),
        "verdict": "near_zero_discount" if discount_rate < 0.005 else "discounted",
    }


def animal_welfare(actions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    costs = []
    for action in actions:
        sentience = max(0.0, min(1.0, float(action.get("sentience", 0.5))))
        harm = max(0.0, float(action.get("harm", 0.0)))
        costs.append(
            {"name": str(action.get("name", "action")), "welfare_cost": round(sentience * harm, 3)}
        )
    total = sum(row["welfare_cost"] for row in costs)
    if total == 0:
        verdict = "no_harm"
    elif total < 1:
        verdict = "minor"
    elif total < 5:
        verdict = "significant"
    else:
        verdict = "severe"
    return {"total": round(total, 3), "actions": costs, "verdict": verdict}


def conflict_of_interest(
    affiliations: Mapping[str, Iterable[str]], decision_maker: str, beneficiaries: Iterable[str]
) -> dict[str, Any]:
    if decision_maker not in affiliations:
        raise EthicsError(f"unknown decision maker {decision_maker!r}")
    personal = {str(org) for org in affiliations[decision_maker]}
    exposed = []
    for beneficiary in beneficiaries:
        organisations = {str(org) for org in affiliations.get(beneficiary, ())}
        shared = sorted(personal & organisations)
        if shared:
            exposed.append({"beneficiary": str(beneficiary), "shared": shared})
    return {
        "conflict": bool(exposed),
        "exposed": exposed,
        "recommendation": "recuse" if exposed else "proceed",
    }


def whistleblowing(
    *,
    severity: float,
    evidence: float,
    channels_exhausted: bool,
    retaliation_risk: float = 0.0,
) -> dict[str, Any]:
    severity = max(0.0, min(1.0, severity))
    evidence = max(0.0, min(1.0, evidence))
    score = severity * evidence + (0.3 if channels_exhausted else 0.0)
    if not channels_exhausted:
        action = "raise_internally"
    elif score >= 0.5:
        action = "escalate_externally"
    else:
        action = "document_and_wait"
    return {
        "score": round(score, 3),
        "action": action,
        "protections_needed": retaliation_risk > 0.3,
        "retaliation_risk": retaliation_risk,
    }


def civil_disobedience(criteria: Mapping[str, bool]) -> dict[str, Any]:
    required = ("injustice", "last_resort", "proportionate", "nonviolent", "accepts_penalty")
    missing = [name for name in required if not criteria.get(name, False)]
    score = round((len(required) - len(missing)) / len(required), 3)
    return {
        "score": score,
        "missing": missing,
        "verdict": "justified" if not missing else ("partial" if score >= 0.6 else "unjustified"),
    }


def moral_courage(
    *, principle_strength: float, personal_cost: float, social_pressure: float
) -> dict[str, Any]:
    score = principle_strength - 0.5 * personal_cost - 0.3 * social_pressure
    return {
        "score": round(score, 3),
        "act": score > 0,
        "verdict": "speak" if score > 0 else "stay_silent",
    }


def moral_learning(
    weights: Sequence[float], features: Sequence[float], feedback: float, *, lr: float = 0.1
) -> dict[str, Any]:
    if len(weights) != len(features):
        raise EthicsError("weights and features must match")
    updated = [weight + lr * feedback * value for weight, value in zip(weights, features)]
    before = sum(w * f for w, f in zip(weights, features))
    after = sum(w * f for w, f in zip(updated, features))
    return {
        "weights": [round(value, 4) for value in updated],
        "score_before": round(before, 4),
        "score_after": round(after, 4),
    }


def moral_evolution(
    population: Sequence[Sequence[float]],
    outcomes: Sequence[float],
    *,
    generations: int = 5,
    mutation: float = 0.1,
    seed: int = 0,
) -> dict[str, Any]:
    if not population:
        raise EthicsError("a population is needed")
    if any(len(candidate) != len(outcomes) for candidate in population):
        raise EthicsError("every candidate must match the outcome vector")
    generator = random.Random(seed)
    current = [list(candidate) for candidate in population]
    best_history = []
    for _ in range(generations):
        fitness = [sum(w * o for w, o in zip(candidate, outcomes)) for candidate in current]
        order = sorted(range(len(current)), key=lambda index: -fitness[index])
        best_history.append(round(fitness[order[0]], 4))
        survivors = [current[index] for index in order[: max(2, len(current) // 2)]]
        children = [list(survivors[0])]
        while len(children) < len(current):
            parent = survivors[generator.randrange(len(survivors))]
            children.append([value + generator.gauss(0.0, mutation) for value in parent])
        current = children
    fitness = [sum(w * o for w, o in zip(candidate, outcomes)) for candidate in current]
    best = max(range(len(current)), key=lambda index: fitness[index])
    return {
        "best": [round(value, 4) for value in current[best]],
        "best_fitness": round(fitness[best], 4),
        "history": best_history,
    }
