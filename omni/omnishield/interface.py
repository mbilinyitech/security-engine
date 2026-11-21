"""Human-facing controls with numbers behind them.

Preference learning, a user model, interruptibility cost, WCAG contrast and
Flesch readability, feature-contribution explanations, operator control,
consent scopes and data minimisation.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class InterfaceError(Exception):
    pass


@dataclass
class Personalizer:
    weights: list[float] = field(default_factory=list)
    learning_rate: float = 0.1
    updates: int = 0

    def _ensure(self, size: int) -> None:
        if not self.weights:
            self.weights = [0.0] * size
        if len(self.weights) != size:
            raise InterfaceError("the feature vector changed size")

    def update(self, features: Sequence[float], rating: float) -> dict[str, Any]:
        if not -1.0 <= rating <= 1.0:
            raise InterfaceError("a rating lives between -1 and 1")
        self._ensure(len(features))
        prediction = sum(w * f for w, f in zip(self.weights, features))
        error = rating - prediction
        self.weights = [
            round(w + self.learning_rate * error * f, 4)
            for w, f in zip(self.weights, features)
        ]
        self.updates += 1
        return {
            "prediction": round(prediction, 4),
            "error": round(error, 4),
            "weights": list(self.weights),
            "updates": self.updates,
        }

    def rank(self, items: Mapping[str, Sequence[float]]) -> list[dict[str, Any]]:
        scored = [
            {"item": name, "score": round(sum(w * f for w, f in zip(self.weights, features)), 4)}
            for name, features in items.items()
        ]
        scored.sort(key=lambda row: -row["score"])
        return scored


class UserModel:
    """Per-skill proficiency from observed outcomes, with a recency weight."""

    def __init__(self) -> None:
        self.skills: dict[str, dict[str, float]] = {}

    def observe(self, skill: str, success: bool, *, weight: float = 1.0) -> dict[str, Any]:
        record = self.skills.setdefault(skill, {"attempts": 0.0, "successes": 0.0, "rate": 0.5})
        record["attempts"] += weight
        record["successes"] += weight if success else 0.0
        record["rate"] = round(record["successes"] / record["attempts"], 4)
        return {"skill": skill, **record}

    def proficiency(self, skill: str) -> float:
        return self.skills.get(skill, {}).get("rate", 0.5)

    def summary(self) -> dict[str, Any]:
        if not self.skills:
            return {"skills": {}, "strongest": None, "weakest": None}
        ordered = sorted(self.skills.items(), key=lambda item: item[1]["rate"])
        return {
            "skills": {name: round(record["rate"], 3) for name, record in sorted(self.skills.items())},
            "strongest": ordered[-1][0],
            "weakest": ordered[0][0],
        }


PHASE_COST = {"focus": 0.9, "meeting": 0.8, "collaborative": 0.4, "idle": 0.1}


def interruptibility(
    phase: str, urgency: float, *, deadline_s: float | None = None
) -> dict[str, Any]:
    if phase not in PHASE_COST:
        raise InterfaceError(f"unknown phase {phase!r}")
    if not 0.0 <= urgency <= 1.0:
        raise InterfaceError("urgency lives between 0 and 1")
    cost = PHASE_COST[phase] * (1.0 - 0.5 * urgency)
    if deadline_s is not None and deadline_s < 60:
        cost *= 0.5
    cost = round(min(max(cost, 0.0), 1.0), 3)
    return {
        "cost": cost,
        "recommendation": "interrupt" if cost < 0.5 else "wait",
        "phase": phase,
        "urgency": urgency,
    }


def _luminance(colour: Sequence[int]) -> float:
    channels = []
    for value in colour[:3]:
        channel = value / 255.0
        channels.append(channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast_ratio(foreground: Sequence[int], background: Sequence[int]) -> dict[str, Any]:
    first = _luminance(foreground)
    second = _luminance(background)
    lighter, darker = max(first, second), min(first, second)
    ratio = round((lighter + 0.05) / (darker + 0.05), 2)
    return {
        "ratio": ratio,
        "aa_normal": ratio >= 4.5,
        "aa_large": ratio >= 3.0,
        "aaa_normal": ratio >= 7.0,
    }


def readability(text: str) -> dict[str, Any]:
    sentences = max(len(re.findall(r"[.!?]+", text)), 1)
    words = re.findall(r"[A-Za-z']+", text)
    if not words:
        raise InterfaceError("there is no readable text")
    syllables = sum(
        max(1, len(re.findall(r"[aeiouy]+", word.lower()))) for word in words
    )
    score = 206.835 - 1.015 * (len(words) / sentences) - 84.6 * (syllables / len(words))
    grade = max(1, math.ceil((0.39 * (len(words) / sentences)) + (11.8 * (syllables / len(words))) - 15.59))
    return {
        "flesch": round(score, 2),
        "grade": grade,
        "words": len(words),
        "sentences": sentences,
        "verdict": "plain" if score >= 60 else ("difficult" if score >= 30 else "very_difficult"),
    }


def explain(
    weights: Sequence[float], features: Sequence[float], *, top: int = 3
) -> dict[str, Any]:
    if len(weights) != len(features):
        raise InterfaceError("weights and features must match")
    contributions = [w * f for w, f in zip(weights, features)]
    total = sum(abs(value) for value in contributions) or 1e-9
    order = sorted(range(len(contributions)), key=lambda index: -abs(contributions[index]))
    reasons = [
        {
            "feature": index,
            "contribution": round(contributions[index], 4),
            "share": round(abs(contributions[index]) / total, 4),
            "direction": "supports" if contributions[index] >= 0 else "opposes",
        }
        for index in order[:top]
    ]
    return {
        "score": round(sum(contributions), 4),
        "reasons": reasons,
        "dominant": reasons[0]["feature"] if reasons else None,
    }


def controllability(action: str, policy: Mapping[str, Iterable[str]]) -> dict[str, Any]:
    allow = set(policy.get("allow", ()))
    deny = set(policy.get("deny", ()))
    confirm = set(policy.get("require_confirmation", ()))
    if action in deny:
        return {"allowed": False, "confirmation_required": False, "reason": "explicitly denied"}
    if allow and action not in allow:
        return {"allowed": False, "confirmation_required": False, "reason": "not on the allow-list"}
    return {
        "allowed": True,
        "confirmation_required": action in confirm,
        "reason": "confirmed" if action in confirm else "permitted",
    }


class ConsentLedger:
    def __init__(self) -> None:
        self.grants: dict[tuple[str, str], set[str]] = {}

    def grant(self, subject: str, purpose: str, scopes: Iterable[str]) -> dict[str, Any]:
        granted = self.grants.setdefault((subject, purpose), set())
        granted.update(scopes)
        return {"subject": subject, "purpose": purpose, "scopes": sorted(granted)}

    def withdraw(self, subject: str, purpose: str) -> dict[str, Any]:
        self.grants.pop((subject, purpose), None)
        return {"subject": subject, "purpose": purpose, "scopes": []}

    def check(self, subject: str, purpose: str, scope: str) -> dict[str, Any]:
        granted = self.grants.get((subject, purpose), set())
        return {
            "allowed": scope in granted,
            "scopes": sorted(granted),
            "reason": "consented" if scope in granted else "no consent for this scope",
        }


def minimise(record: Mapping[str, Any], allowed: Iterable[str]) -> dict[str, Any]:
    keep = set(allowed)
    kept = {key: value for key, value in record.items() if key in keep}
    return {"record": kept, "dropped": sorted(set(record) - keep)}


def retention_expired(created_at: float, now: float, *, days: int) -> dict[str, Any]:
    age = max(0.0, now - created_at)
    limit = days * 86_400
    return {
        "age_days": round(age / 86_400, 2),
        "expired": age > limit,
        "remaining_days": round(max(0.0, limit - age) / 86_400, 2),
    }
