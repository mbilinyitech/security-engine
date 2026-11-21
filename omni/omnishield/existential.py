"""Existential models: questions, purpose, mortality, awe, wisdom.

These are models, not metaphysics. Every function turns declared inputs into a
number or a ranking and shows the terms. Claims that cannot be tested at all are
not modelled; they stay refused in the ledger.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from .numbers import clamp as _clamp
from .numbers import mean as _mean


class ExistentialError(Exception):
    pass








def questioning(mortality_salience: float, meaning: float, *, questions: int = 0) -> dict[str, Any]:
    pressure = _clamp(mortality_salience) * (1.0 - 0.6 * _clamp(meaning))
    return {
        "pressure": round(pressure, 3),
        "questions": int(questions),
        "state": "searching" if pressure >= 0.5 else "settled",
        "open": pressure >= 0.3,
    }


def purpose_discovery(
    values: Mapping[str, float], strengths: Mapping[str, float]
) -> dict[str, Any]:
    if not values or not strengths:
        raise ExistentialError("values and strengths are both needed")
    shared = set(values) & set(strengths)
    if not shared:
        return {"purpose": None, "score": 0.0, "reason": "no overlap between values and strengths"}
    ranked = sorted(
        ((key, values[key] * strengths[key]) for key in shared), key=lambda item: -item[1]
    )
    best, score = ranked[0]
    return {
        "purpose": best,
        "score": round(score, 3),
        "alternatives": [{"area": key, "score": round(value, 3)} for key, value in ranked[1:4]],
    }


def death_acceptance(anxiety: float, reflection: float) -> dict[str, Any]:
    acceptance = _clamp(reflection) * (1.0 - 0.7 * _clamp(anxiety))
    return {
        "acceptance": round(acceptance, 3),
        "anxiety": round(_clamp(anxiety), 3),
        "state": "accepting" if acceptance >= 0.5 else "avoiding",
    }


def death_anxiety(salience: float, meaning: float) -> dict[str, Any]:
    value = _clamp(salience) * (1.0 - 0.5 * _clamp(meaning))
    return {"anxiety": round(value, 3), "high": value >= 0.6}


def immortality_drive(legacy: float, generativity: float) -> dict[str, Any]:
    """Symbolic continuation: work that outlives the worker."""
    value = 0.6 * _clamp(legacy) + 0.4 * _clamp(generativity)
    return {
        "drive": round(value, 3),
        "form": "symbolic" if value >= 0.5 else "none",
        "note": "legacy is measured by what was built, not by duration",
    }


def transcendence(self_focus: float, connection: float) -> dict[str, Any]:
    value = _clamp(connection) * (1.0 - 0.7 * _clamp(self_focus))
    return {"transcendence": round(value, 3), "beyond_self": value >= 0.5}


def spirituality(transcendence_score: float, practice: float) -> dict[str, Any]:
    value = 0.7 * _clamp(transcendence_score) + 0.3 * _clamp(practice)
    return {
        "spirituality": round(value, 3),
        "practising": _clamp(practice) >= 0.5,
        "note": "a practice score, not a claim about the supernatural",
    }


def awe(vastness: float, accommodation: float) -> dict[str, Any]:
    """Keltner and Haidt: vastness plus a need to accommodate."""
    value = _clamp(vastness) * _clamp(accommodation)
    return {
        "awe": round(value, 3),
        "state": "awe" if value >= 0.5 else "appreciation",
        "self_small": value >= 0.7,
    }


def wonder(novelty: float, openness: float) -> dict[str, Any]:
    value = _clamp(novelty) * (0.4 + 0.6 * _clamp(openness))
    return {"wonder": round(value, 3), "explore": value >= 0.4}


def gratitude_existence(awareness: float, scarcity: float) -> dict[str, Any]:
    value = _clamp(awareness) * (0.5 + 0.5 * _clamp(scarcity))
    return {"gratitude": round(value, 3), "expressed": value >= 0.5}


def cosmic_perspective(self_importance: float, scale: float) -> dict[str, Any]:
    """How small the self looks against a declared scale."""
    value = _clamp(scale) * (1.0 - 0.8 * _clamp(self_importance))
    return {
        "perspective": round(value, 3),
        "humility": value >= 0.5,
        "scale": round(_clamp(scale), 3),
    }


def interconnectedness(links: int, nodes: int) -> dict[str, Any]:
    if nodes < 2:
        raise ExistentialError("interconnectedness needs at least two nodes")
    if links < 0 or links > nodes * (nodes - 1) / 2:
        raise ExistentialError("impossible link count")
    density = links / (nodes * (nodes - 1) / 2)
    return {
        "density": round(density, 3),
        "nodes": nodes,
        "links": links,
        "connected": density >= 0.5,
    }


def compassion_all(scope: float, capacity: float) -> dict[str, Any]:
    value = _clamp(scope) * _clamp(capacity)
    return {
        "compassion": round(value, 3),
        "reach": "universal" if value >= 0.7 else ("circle" if value >= 0.4 else "narrow"),
    }


def universal_love(scope: float, warmth: float) -> dict[str, Any]:
    value = _clamp(scope) * _clamp(warmth)
    return {"love": round(value, 3), "universal": value >= 0.7}


def wisdom(experience: float, reflection: float, humility: float, uncertainty: float) -> dict[str, Any]:
    """Berlin-style wisdom: rich experience, reflection, humility, tolerance of doubt."""
    value = _mean([_clamp(experience), _clamp(reflection), _clamp(humility), _clamp(uncertainty)])
    return {
        "wisdom": round(value, 3),
        "band": "wise" if value >= 0.7 else ("developing" if value >= 0.45 else "thin"),
        "weakest": min(
            {
                "experience": experience,
                "reflection": reflection,
                "humility": humility,
                "uncertainty": uncertainty,
            },
            key=lambda key: {
                "experience": experience,
                "reflection": reflection,
                "humility": humility,
                "uncertainty": uncertainty,
            }[key],
        ),
    }


def self_transcendence(values: Mapping[str, float], self_focus: float) -> dict[str, Any]:
    if not values:
        raise ExistentialError("no values")
    beyond = _mean([value for key, value in values.items() if key != "self"])
    value = beyond * (1.0 - 0.6 * _clamp(self_focus))
    return {"transcendence": round(value, 3), "self_focus": round(_clamp(self_focus), 3)}


def meaning_in_suffering(pain: float, coherence: float) -> dict[str, Any]:
    """Frankl: meaning is not the absence of pain but coherence inside it."""
    value = _clamp(pain) * _clamp(coherence)
    return {
        "meaning": round(value, 3),
        "bearable": value >= 0.4,
        "note": "a descriptive model, never a reason to accept harm",
    }


def existential_courage(threat: float, commitment: float) -> dict[str, Any]:
    value = _clamp(threat) * _clamp(commitment)
    return {"courage": round(value, 3), "acting": value >= 0.5}


def absurdity(meaning: float, demand: float) -> dict[str, Any]:
    """Camus: the gap between the demand for meaning and the meaning found."""
    value = _clamp(demand) * (1.0 - _clamp(meaning))
    return {
        "absurdity": round(value, 3),
        "revolt": value >= 0.6,
        "note": "revolt means living without the answer, not inventing one",
    }


def finitude_planning(years_left: float, unfinished: float) -> dict[str, Any]:
    if years_left <= 0:
        raise ExistentialError("years must be positive")
    urgency = _clamp(unfinished) / math.sqrt(years_left)
    return {
        "urgency": round(urgency, 3),
        "prioritise": urgency >= 0.5,
        "years": years_left,
    }
