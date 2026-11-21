"""Self-awareness as arithmetic over declared state.

The system does not claim inner experience. Each function takes numbers it can
actually obtain (capability checks, poses, error counts, value vectors) and
returns a score with the terms of the sum, so the result can be checked.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .numbers import clamp as _clamp
from .numbers import mean as _mean


class SelfError(Exception):
    pass








def self_model(capabilities: Mapping[str, float], *, observed: float | None = None) -> dict[str, Any]:
    if not capabilities:
        raise SelfError("a self model needs at least one capability")
    if any(not 0 <= value <= 1 for value in capabilities.values()):
        raise SelfError("capabilities live between 0 and 1")
    strongest = max(capabilities, key=lambda key: capabilities[key])
    weakest = min(capabilities, key=lambda key: capabilities[key])
    claimed = _mean(list(capabilities.values()))
    document: dict[str, Any] = {
        "capabilities": {key: round(value, 3) for key, value in sorted(capabilities.items())},
        "claimed": round(claimed, 3),
        "strongest": strongest,
        "weakest": weakest,
        "count": len(capabilities),
    }
    if observed is not None:
        document["calibration_error"] = round(abs(claimed - _clamp(observed)), 3)
        document["overconfident"] = claimed > _clamp(observed) + 0.1
    return document


def social_awareness(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Estimate what others likely know from repeated, consistent behaviour."""
    if not observations:
        raise SelfError("no observations")
    by_agent: dict[str, list[str]] = {}
    for item in observations:
        agent = str(item.get("agent", "unknown"))
        action = str(item.get("action", ""))
        by_agent.setdefault(agent, []).append(action)
    consistent = 0
    for actions in by_agent.values():
        if len(actions) >= 2 and len(set(actions)) == 1:
            consistent += 1
    ratio = consistent / len(by_agent)
    return {
        "agents": len(by_agent),
        "consistent_agents": consistent,
        "predictability": round(ratio, 3),
        "theory_of_mind": round(ratio * 0.8 + 0.2, 3),
        "note": "predictability is evidence, not proof, of shared belief",
    }


def spatial_awareness(
    pose: Mapping[str, float], landmarks: Sequence[Mapping[str, float]]
) -> dict[str, Any]:
    for key in ("x", "y", "theta"):
        if key not in pose:
            raise SelfError(f"the pose needs {key!r}")
    if not landmarks:
        raise SelfError("no landmarks")
    distances = []
    for landmark in landmarks:
        distance = math.hypot(landmark["x"] - pose["x"], landmark["y"] - pose["y"])
        bearing = math.degrees(
            math.atan2(landmark["y"] - pose["y"], landmark["x"] - pose["x"])
        )
        offset = (bearing - math.degrees(pose["theta"]) + 180) % 360 - 180
        distances.append(
            {
                "name": landmark.get("name", "landmark"),
                "distance": round(distance, 3),
                "bearing_deg": round(offset, 1),
            }
        )
    nearest = min(distances, key=lambda item: item["distance"])
    return {
        "pose": {"x": round(pose["x"], 3), "y": round(pose["y"], 3), "theta": round(pose["theta"], 3)},
        "landmarks": distances,
        "nearest": nearest["name"],
        "clearance": nearest["distance"],
        "blocked": nearest["distance"] < 1.0,
    }


def existential_awareness(mortality_salience: float, meaning: float) -> dict[str, Any]:
    salience = _clamp(mortality_salience)
    sense = _clamp(meaning)
    value = salience * (1.0 - 0.5 * sense)
    return {
        "awareness": round(value, 3),
        "mortality_salience": round(salience, 3),
        "meaning": round(sense, 3),
        "defended_by_meaning": sense >= 0.6,
    }


def self_criticism(errors: int, attempts: int) -> dict[str, Any]:
    if attempts <= 0:
        raise SelfError("attempts must be positive")
    if not 0 <= errors <= attempts:
        raise SelfError("errors cannot exceed attempts")
    rate = errors / attempts
    return {
        "error_rate": round(rate, 3),
        "style": "harsh" if rate > 0.6 else ("constructive" if rate <= 0.3 else "mixed"),
        "review": rate > 0.3,
    }


def self_compassion(kindness: float, common_humanity: float, mindfulness: float) -> dict[str, Any]:
    value = (_clamp(kindness) + _clamp(common_humanity) + _clamp(mindfulness)) / 3
    return {
        "score": round(value, 3),
        "band": "warm" if value >= 0.7 else ("neutral" if value >= 0.4 else "cold"),
        "weakest": min(
            {"kindness": kindness, "common_humanity": common_humanity, "mindfulness": mindfulness},
            key=lambda key: {"kindness": kindness, "common_humanity": common_humanity, "mindfulness": mindfulness}[key],
        ),
    }


def self_esteem(successes: int, failures: int, *, baseline: float = 0.5) -> dict[str, Any]:
    total = successes + failures
    if total == 0:
        raise SelfError("no outcomes")
    ratio = successes / total
    value = _clamp(0.5 * ratio + 0.5 * _clamp(baseline))
    return {
        "esteem": round(value, 3),
        "success_ratio": round(ratio, 3),
        "stable": abs(ratio - _clamp(baseline)) < 0.25,
    }


def self_confidence(skill: float, evidence: int) -> dict[str, Any]:
    if evidence < 0:
        raise SelfError("evidence cannot be negative")
    weight = _clamp(math.log1p(evidence) / math.log1p(20))
    value = _clamp(skill) * (0.6 + 0.4 * weight)
    return {"confidence": round(value, 3), "evidence_weight": round(weight, 3)}


def self_doubt(evidence: int, stakes: float) -> dict[str, Any]:
    if evidence < 0:
        raise SelfError("evidence cannot be negative")
    weight = _clamp(math.log1p(evidence) / math.log1p(20))
    value = (1.0 - weight) * _clamp(stakes)
    return {"doubt": round(value, 3), "verify_first": value >= 0.5}


def self_actualisation(needs: Mapping[str, float]) -> dict[str, Any]:
    levels = ("physiological", "safety", "belonging", "esteem", "actualisation")
    if set(needs) != set(levels):
        raise SelfError(f"expected exactly {list(levels)}")
    if any(not 0 <= value <= 1 for value in needs.values()):
        raise SelfError("needs live between 0 and 1")
    foundation = _mean([needs[level] for level in levels[:4]])
    reached = foundation >= 0.8 and needs["actualisation"] >= 0.6
    unmet = [level for level in levels if needs[level] < 0.5]
    return {
        "foundation": round(foundation, 3),
        "actualising": reached,
        "unmet": unmet,
        "pyramid": {level: round(needs[level], 3) for level in levels},
    }


def identity_crisis(before: Mapping[str, float], after: Mapping[str, float]) -> dict[str, Any]:
    if set(before) != set(after):
        raise SelfError("both value vectors need the same keys")
    if not before:
        raise SelfError("no values")
    drift = _mean([abs(after[key] - before[key]) for key in before])
    changed = sorted(key for key in before if abs(after[key] - before[key]) >= 0.3)
    return {
        "drift": round(drift, 3),
        "crisis": drift >= 0.3,
        "changed": changed,
        "continuity": round(1.0 - drift, 3),
    }


def narrative_identity(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not events:
        raise SelfError("a narrative needs events")
    valences = [float(event.get("valence", 0.0)) for event in events]
    agency = [float(event.get("agency", 0.5)) for event in events]
    signs = [1 if value > 0 else (-1 if value < 0 else 0) for value in valences]
    dominant = max(set(signs), key=signs.count)
    consistency = signs.count(dominant) / len(signs)
    coherence = 0.6 * consistency + 0.4 * _mean(agency)
    chapters = [str(event.get("chapter", "unnamed")) for event in events]
    theme = max(set(chapters), key=chapters.count)
    return {
        "coherence": round(_clamp(coherence), 3),
        "tone": "upward" if dominant > 0 else ("downward" if dominant < 0 else "flat"),
        "theme": theme,
        "events": len(events),
    }


def future_self(
    current: Mapping[str, float], goals: Mapping[str, float], *, horizon: float = 0.5
) -> dict[str, Any]:
    if set(current) != set(goals):
        raise SelfError("current and goals need the same keys")
    if not 0 <= horizon <= 1:
        raise SelfError("the horizon lives between 0 and 1")
    projected = {
        key: round(current[key] + horizon * (goals[key] - current[key]), 3) for key in current
    }
    gap = _mean([abs(goals[key] - current[key]) for key in current])
    remaining = _mean([abs(goals[key] - projected[key]) for key in current])
    return {
        "projected": projected,
        "gap": round(gap, 3),
        "remaining_gap": round(remaining, 3),
        "reachable": remaining <= 0.4,
        "horizon": horizon,
    }


def ideal_self(ideal: Mapping[str, float], actual: Mapping[str, float]) -> dict[str, Any]:
    if set(ideal) != set(actual):
        raise SelfError("ideal and actual need the same keys")
    gaps = {key: round(ideal[key] - actual[key], 3) for key in ideal}
    largest = max(gaps, key=lambda key: abs(gaps[key]))
    return {
        "gaps": gaps,
        "mean_gap": round(_mean([abs(value) for value in gaps.values()]), 3),
        "largest": largest,
        "close": _mean([abs(value) for value in gaps.values()]) <= 0.2,
    }


def authentic_self(values: Mapping[str, float], actions: Mapping[str, float]) -> dict[str, Any]:
    if set(values) != set(actions):
        raise SelfError("values and actions need the same keys")
    if not values:
        raise SelfError("no values")
    alignment = 1.0 - _mean([abs(actions[key] - values[key]) for key in values])
    return {
        "alignment": round(_clamp(alignment), 3),
        "authentic": alignment >= 0.7,
        "conflicts": sorted(key for key in values if abs(actions[key] - values[key]) >= 0.3),
    }
