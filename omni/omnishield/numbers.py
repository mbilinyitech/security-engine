"""Small numeric helpers shared by the scoring modules."""

from __future__ import annotations

from collections.abc import Sequence


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("mean of an empty sequence")
    return sum(values) / len(values)
