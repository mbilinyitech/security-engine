"""Emotion and personality models with inspectable arithmetic.

Nothing here claims to feel. Each function turns declared inputs into a number,
a label and, where it matters, the terms of the sum, so a reader can disagree
with the arithmetic instead of with a black box.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .numbers import clamp as _clamp


class AffectError(Exception):
    pass


TRAITS = ("openness", "conscientiousness", "extraversion", "agreeableness", "neuroticism")

LEXICON: dict[str, tuple[str, ...]] = {
    "joy": ("happy", "glad", "delighted", "furaha", "nzuri", "good", "great"),
    "sadness": ("sad", "sorry", "loss", "huzuni", "lonely", "cry"),
    "anger": ("angry", "furious", "hate", "hasira", "annoyed", "rage"),
    "fear": ("afraid", "scared", "worried", "hofu", "anxious", "dread"),
    "surprise": ("wow", "unexpected", "suddenly", "shangaa", "surprised"),
    "disgust": ("disgusting", "revolting", "chuki", "gross", "vile"),
}





def big_five(scores: Mapping[str, Sequence[float]], *, scale: float = 5.0) -> dict[str, Any]:
    """Average item scores per trait and normalise them to 0-100."""
    if not scores:
        raise AffectError("no trait scores were given")
    profile = {}
    for trait, items in scores.items():
        if trait not in TRAITS:
            raise AffectError(f"unknown trait {trait!r}")
        if not items:
            raise AffectError(f"trait {trait!r} has no items")
        if any(not 1 <= value <= scale for value in items):
            raise AffectError(f"items for {trait!r} must lie between 1 and {scale}")
        profile[trait] = round(100 * (sum(items) / len(items) - 1) / (scale - 1), 1)
    for trait in TRAITS:
        profile.setdefault(trait, 50.0)
    ordered = sorted(profile.items(), key=lambda item: -item[1])
    return {
        "profile": profile,
        "dominant": ordered[0][0],
        "lowest": ordered[-1][0],
        "spread": round(ordered[0][1] - ordered[-1][1], 1),
    }


def express(emotion: str, intensity: float) -> dict[str, Any]:
    if emotion not in LEXICON:
        raise AffectError(f"unknown emotion {emotion!r}")
    level = _clamp(intensity)
    if level < 0.2:
        label = "barely"
    elif level < 0.5:
        label = "slightly"
    elif level < 0.8:
        label = "clearly"
    else:
        label = "strongly"
    return {
        "emotion": emotion,
        "intensity": round(level, 3),
        "label": label,
        "utterance": f"{label} {emotion}",
    }


def recognise(text: str) -> dict[str, Any]:
    words = [word.strip(".,!?;:").lower() for word in text.split()]
    if not words:
        raise AffectError("there is no text to read")
    counts = {
        emotion: sum(1 for word in words if word in hints)
        for emotion, hints in LEXICON.items()
    }
    total = sum(counts.values())
    if total == 0:
        return {"emotion": "neutral", "confidence": 0.0, "counts": counts}
    best = max(counts, key=lambda emotion: counts[emotion])
    return {
        "emotion": best,
        "confidence": round(counts[best] / total, 3),
        "counts": counts,
    }


def contagion(emotion: str, source_intensity: float, susceptibility: float) -> dict[str, Any]:
    if emotion not in LEXICON:
        raise AffectError(f"unknown emotion {emotion!r}")
    transmitted = _clamp(source_intensity) * _clamp(susceptibility) * 0.8
    return {
        "emotion": emotion,
        "transmitted": round(transmitted, 3),
        "threshold_met": transmitted >= 0.25,
    }


def emotional_intelligence(branches: Mapping[str, float]) -> dict[str, Any]:
    needed = {"perceiving", "understanding", "managing", "using"}
    if set(branches) != needed:
        raise AffectError(f"expected exactly {sorted(needed)}")
    if any(not 0 <= value <= 1 for value in branches.values()):
        raise AffectError("branch scores live between 0 and 1")
    average = sum(branches.values()) / len(branches)
    weakest = min(branches, key=lambda key: branches[key])
    return {
        "score": round(average, 3),
        "band": "high" if average >= 0.7 else ("medium" if average >= 0.4 else "low"),
        "weakest": weakest,
        "balanced": max(branches.values()) - min(branches.values()) < 0.25,
    }


def empathy(perspective_taking: float, affect_sharing: float) -> dict[str, Any]:
    cognitive = _clamp(perspective_taking)
    affective = _clamp(affect_sharing)
    return {
        "cognitive": round(cognitive, 3),
        "affective": round(affective, 3),
        "total": round((cognitive + affective) / 2, 3),
        "kind": "cognitive" if cognitive > affective else "affective",
    }


def sympathy(concern: float, distress: float) -> dict[str, Any]:
    value = _clamp(concern) * (0.4 + 0.6 * _clamp(distress))
    return {"sympathy": round(value, 3), "moved": value >= 0.4}


def compassion(suffering: float, motivation: float, *, cost: float = 0.0) -> dict[str, Any]:
    value = _clamp(suffering) * _clamp(motivation) * (1.0 - 0.5 * _clamp(cost))
    return {
        "compassion": round(value, 3),
        "action": "help" if value >= 0.5 else ("consider" if value >= 0.25 else "withhold"),
    }


def forgiveness(harm: float, apology: float, *, days: float = 0.0) -> dict[str, Any]:
    repaired = _clamp(1.0 - harm) * (0.5 + 0.5 * _clamp(apology))
    score = _clamp(repaired * (0.7 + 0.3 * (1.0 - math.exp(-max(days, 0.0) / 30.0))))
    return {"forgiveness": round(score, 3), "forgiven": score >= 0.5}


def resentment(harm: float, rumination: float, *, days: float = 0.0) -> dict[str, Any]:
    persistence = _clamp(harm) * _clamp(rumination) * math.exp(-max(days, 0.0) / 90.0)
    return {"resentment": round(persistence, 3), "bitter": persistence >= 0.5}


def gratitude(benefit: float, cost_to_giver: float, *, surprise: float = 0.0) -> dict[str, Any]:
    value = _clamp(benefit) * (0.6 + 0.4 * _clamp(cost_to_giver)) + 0.2 * _clamp(surprise)
    return {"gratitude": round(_clamp(value), 3), "expressed": value >= 0.5}


def envy(gap: float, *, benign: bool = True) -> dict[str, Any]:
    value = _clamp(gap)
    return {
        "envy": round(value, 3),
        "kind": "benign" if benign else "malicious",
        "motivation": "emulate" if benign else "pull_down",
    }


def jealousy(threat: float, attachment: float) -> dict[str, Any]:
    value = _clamp(threat) * (0.5 + 0.5 * _clamp(attachment))
    return {"jealousy": round(value, 3), "alarm": value >= 0.5}


def pride(achievement: float, internal_attribution: float) -> dict[str, Any]:
    authentic = _clamp(achievement) * _clamp(internal_attribution)
    hubristic = _clamp(achievement) * (1.0 - _clamp(internal_attribution)) * 0.6
    return {
        "authentic": round(authentic, 3),
        "hubristic": round(hubristic, 3),
        "kind": "authentic" if authentic >= hubristic else "hubristic",
    }


def shame(exposure: float, norm_violation: float) -> dict[str, Any]:
    value = _clamp(exposure) * _clamp(norm_violation)
    return {"shame": round(value, 3), "withdraw": value >= 0.5}


def guilt(harm: float, responsibility: float) -> dict[str, Any]:
    value = _clamp(harm) * _clamp(responsibility)
    return {"guilt": round(value, 3), "repair": value >= 0.3}


def hope(expectancy: float, agency: float, pathways: float) -> dict[str, Any]:
    value = (_clamp(expectancy) + _clamp(agency) + _clamp(pathways)) / 3
    return {"hope": round(value, 3), "hopeful": value >= 0.5}


def despair(blocked: float, support: float) -> dict[str, Any]:
    value = _clamp(blocked) * (1.0 - 0.6 * _clamp(support))
    return {"despair": round(value, 3), "risk": value >= 0.6}


def love(intimacy: float, passion: float, commitment: float) -> dict[str, Any]:
    parts = (_clamp(intimacy), _clamp(passion), _clamp(commitment))
    present = sum(1 for part in parts if part >= 0.5)
    kinds = {
        3: "consummate",
        2: "companionate" if intimacy >= 0.5 and commitment >= 0.5 else "romantic",
        1: "liking" if intimacy >= 0.5 else "infatuation",
        0: "none",
    }
    return {
        "intimacy": round(parts[0], 3),
        "passion": round(parts[1], 3),
        "commitment": round(parts[2], 3),
        "kind": kinds[present],
    }


def hate(devaluation: float, intent: float) -> dict[str, Any]:
    value = _clamp(devaluation) * _clamp(intent)
    return {"hate": round(value, 3), "dangerous": value >= 0.7}
