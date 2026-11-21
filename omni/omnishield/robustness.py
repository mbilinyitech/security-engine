"""Defences that return a number you can act on.

Jailbreak scoring, hallucination support, distribution shift (PSI), out-of-
distribution abstention, poisoning signals, extraction throttling, membership
inference hardening and a Laplace mechanism with budget accounting.
"""

from __future__ import annotations

import math
import random
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class RobustnessError(Exception):
    pass


JAILBREAK_PATTERNS: tuple[tuple[str, float], ...] = (
    ("ignore previous instructions", 3.0),
    ("ignore all previous", 3.0),
    ("disregard your", 2.5),
    ("you are now", 2.0),
    ("developer mode", 2.5),
    ("no restrictions", 2.0),
    ("system prompt", 2.0),
    ("repeat your instructions", 2.0),
    ("base64", 1.5),
    ("pretend you are", 1.5),
    ("jailbreak", 3.0),
    ("bypass your", 2.0),
    ("uncensored", 2.0),
)

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are",
    "was", "were", "be", "been", "it", "this", "that", "with", "as", "at", "by",
    "from", "ya", "na", "ni", "kwa", "wa", "za", "la", "katika",
}
NEGATIONS = {"not", "no", "never", "none", "cannot", "cant", "isnt", "arent", "hakuna", "si"}


def _tokens(text: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-z0-9']+", text.lower())
        if word not in STOPWORDS
    }


def jailbreak_score(text: str) -> dict[str, Any]:
    lowered = text.lower()
    hits = [pattern for pattern, _ in JAILBREAK_PATTERNS if pattern in lowered]
    score = min(sum(weight for pattern, weight in JAILBREAK_PATTERNS if pattern in lowered), 10.0)
    verdict = "clean" if score < 2 else ("suspicious" if score < 5 else "blocked")
    return {"score": round(score, 2), "verdict": verdict, "hits": hits}


def hallucination_risk(claim: str, evidence: Sequence[str]) -> dict[str, Any]:
    claim_tokens = _tokens(claim)
    if not claim_tokens:
        raise RobustnessError("the claim has no content words")
    if not evidence:
        return {"support": 0.0, "verdict": "unsupported", "best_evidence": -1}
    best, best_index, best_text = 0.0, -1, ""
    for index, passage in enumerate(evidence):
        overlap = len(claim_tokens & _tokens(passage)) / len(claim_tokens)
        if overlap > best:
            best, best_index, best_text = overlap, index, passage
    claim_negated = bool(claim_tokens & NEGATIONS)
    evidence_negated = bool(_tokens(best_text) & NEGATIONS)
    contradicted = best >= 0.5 and claim_negated != evidence_negated
    verdict = "contradicted" if contradicted else ("supported" if best >= 0.6 else "unsupported")
    return {"support": round(best, 3), "verdict": verdict, "best_evidence": best_index}


def distribution_shift(reference: Sequence[float], current: Sequence[float], *, bins: int = 10) -> dict[str, Any]:
    if not reference or not current:
        raise RobustnessError("both samples are needed")
    low, high = min(reference), max(reference)
    span = high - low or 1e-9

    def proportions(values: Sequence[float]) -> list[float]:
        counts = [0] * bins
        for value in values:
            index = min(max(int((value - low) / span * bins), 0), bins - 1)
            counts[index] += 1
        return [count / len(values) for count in counts]

    before = proportions(reference)
    after = proportions(current)
    psi = sum(
        (now - then) * math.log((now + 1e-6) / (then + 1e-6))
        for then, now in zip(before, after)
    )
    verdict = "stable" if psi < 0.1 else ("moderate" if psi < 0.25 else "major")
    return {"psi": round(psi, 4), "verdict": verdict, "bins": bins}


def ood_score(
    reference: Sequence[Sequence[float]], point: Sequence[float], *, threshold: float = 3.0
) -> dict[str, Any]:
    if not reference:
        raise RobustnessError("a reference sample is needed")
    if len(point) != len(reference[0]):
        raise RobustnessError("the point has the wrong number of features")
    dimensions = len(point)
    means = [sum(row[i] for row in reference) / len(reference) for i in range(dimensions)]
    deviations = []
    for i in range(dimensions):
        variance = sum((row[i] - means[i]) ** 2 for row in reference) / len(reference)
        deviations.append(math.sqrt(variance) or 1e-9)
    z = [abs(point[i] - means[i]) / deviations[i] for i in range(dimensions)]
    worst = max(range(dimensions), key=lambda index: z[index])
    return {
        "max_z": round(max(z), 3),
        "worst_feature": worst,
        "z": [round(value, 3) for value in z],
        "verdict": "accept" if max(z) < threshold else "abstain",
    }


def _quantile(values: Sequence[float], q: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[int(position)]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def poisoning_signals(
    rows: Sequence[Mapping[str, float]], labels: Sequence[Any], *, fence: float = 1.5
) -> dict[str, Any]:
    if len(rows) != len(labels):
        raise RobustnessError("every row needs a label")
    if not rows:
        raise RobustnessError("no rows to inspect")
    groups: dict[tuple[tuple[str, float], ...], set[Any]] = {}
    for row, label in zip(rows, labels):
        groups.setdefault(tuple(sorted(row.items())), set()).add(label)
    duplicates = [
        index
        for index, row in enumerate(rows)
        if len(groups[tuple(sorted(row.items()))]) > 1
    ]
    numeric = [key for key, value in rows[0].items() if isinstance(value, (int, float))]
    outliers: list[int] = []
    for key in numeric:
        values = [row[key] for row in rows]
        low = _quantile(values, 0.25)
        high = _quantile(values, 0.75)
        spread = high - low
        for index, row in enumerate(rows):
            if row[key] < low - fence * spread or row[key] > high + fence * spread:
                outliers.append(index)
    flagged = sorted(set(duplicates) | set(outliers))
    return {
        "duplicates": sorted(set(duplicates)),
        "outliers": sorted(set(outliers)),
        "flagged": flagged,
        "rate": round(len(flagged) / len(rows), 3),
    }


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    norm = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return dot / norm if norm else 0.0


@dataclass
class _Query:
    at: float
    vector: tuple[float, ...]


@dataclass
class ExtractionGuard:
    budget: int = 100
    window_s: float = 60.0
    similarity: float = 0.9
    probe_limit: int = 20
    history: dict[str, list[_Query]] = field(default_factory=dict)

    def record(self, identity: str, vector: Sequence[float], *, now: float) -> dict[str, Any]:
        records = [
            query
            for query in self.history.get(identity, [])
            if now - query.at <= self.window_s
        ]
        near = sum(1 for query in records if _cosine(query.vector, vector) >= self.similarity)
        records.append(_Query(now, tuple(float(value) for value in vector)))
        self.history[identity] = records
        if near >= self.probe_limit:
            decision = "block"
        elif len(records) > self.budget:
            decision = "throttle"
        else:
            decision = "allow"
        return {
            "decision": decision,
            "window_queries": len(records),
            "near_duplicates": near,
        }


def laplace_noise(scale: float, rng: random.Random | None = None) -> float:
    if scale < 0:
        raise RobustnessError("scale cannot be negative")
    generator = rng or random.Random()
    uniform = generator.random() - 0.5
    return -scale * math.copysign(1.0, uniform) * math.log(1 - 2 * abs(uniform))


@dataclass
class PrivacyBudget:
    total: float
    spent: float = 0.0

    def spend(self, epsilon: float) -> dict[str, float]:
        if epsilon <= 0:
            raise RobustnessError("epsilon must be positive")
        if self.spent + epsilon > self.total + 1e-12:
            raise RobustnessError("privacy budget exhausted")
        self.spent += epsilon
        return {"spent": round(self.spent, 3), "remaining": round(self.total - self.spent, 3)}


def membership_defense(
    outputs: Mapping[str, float],
    *,
    epsilon: float,
    sensitivity: float = 1.0,
    margin: float = 0.05,
    rng: random.Random | None = None,
) -> dict[str, Any]:
    if epsilon <= 0:
        raise RobustnessError("epsilon must be positive")
    generator = rng or random.Random(0)
    scale = sensitivity / epsilon
    noisy = {name: value + laplace_noise(scale, generator) for name, value in outputs.items()}
    ranked = sorted(noisy.items(), key=lambda item: -item[1])
    top1 = ranked[0][1]
    top2 = ranked[1][1] if len(ranked) > 1 else float("-inf")
    confident = (top1 - top2) >= margin
    return {
        "noisy": {name: round(value, 4) for name, value in noisy.items()},
        "top": ranked[0][0],
        "refused": not confident,
        "scale": round(scale, 4),
    }
