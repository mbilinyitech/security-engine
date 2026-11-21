"""Prediction that is scored against reality.

Every function here produces a number and the check that can falsify it: a
forecast with its residuals, a probability with its Brier score, an anomaly with
its z-score, a fused estimate with its uncertainty. Nothing is reported as
"predicted" unless an observation was compared to it.
"""

from __future__ import annotations

import math
import statistics
import time
from collections.abc import Mapping, Sequence
from typing import Any

from .inspect import snapshot


class PredictError(Exception):
    pass


def ewma(series: Sequence[float], *, alpha: float = 0.3) -> dict[str, Any]:
    if not series:
        raise PredictError("the series is empty")
    if not 0 < alpha <= 1:
        raise PredictError("alpha must lie in (0, 1]")
    smoothed = [float(series[0])]
    for value in series[1:]:
        smoothed.append(alpha * float(value) + (1 - alpha) * smoothed[-1])
    return {
        "smoothed": [round(value, 4) for value in smoothed],
        "next": round(smoothed[-1], 4),
        "alpha": alpha,
    }


def linear_forecast(series: Sequence[float], *, horizon: int = 1) -> dict[str, Any]:
    values = [float(value) for value in series]
    if len(values) < 2:
        raise PredictError("a forecast needs at least two points")
    if horizon < 1:
        raise PredictError("the horizon must be positive")
    xs = list(range(len(values)))
    mean_x = sum(xs) / len(xs)
    mean_y = sum(values) / len(values)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, values, strict=True)) / denominator
    intercept = mean_y - slope * mean_x
    residuals = [y - (intercept + slope * x) for x, y in zip(xs, values, strict=True)]
    total = sum((y - mean_y) ** 2 for y in values)
    r2 = 1.0 - (sum(error**2 for error in residuals) / total) if total else 1.0
    forecast = [round(intercept + slope * (len(values) - 1 + step), 4) for step in range(1, horizon + 1)]
    return {
        "slope": round(slope, 6),
        "intercept": round(intercept, 6),
        "r2": round(max(-1.0, min(1.0, r2)), 4),
        "residual_std": round(statistics.pstdev(residuals), 4),
        "forecast": forecast,
        "direction": "up" if slope > 0 else ("down" if slope < 0 else "flat"),
    }


def brier_score(probabilities: Sequence[float], outcomes: Sequence[int]) -> dict[str, Any]:
    if len(probabilities) != len(outcomes) or not probabilities:
        raise PredictError("one probability per outcome is required")
    if any(not 0 <= probability <= 1 for probability in probabilities):
        raise PredictError("probabilities live between 0 and 1")
    if any(outcome not in (0, 1) for outcome in outcomes):
        raise PredictError("outcomes are 0 or 1")
    score = sum((p - o) ** 2 for p, o in zip(probabilities, outcomes, strict=True)) / len(probabilities)
    base = sum(outcomes) / len(outcomes)
    baseline = base * (1 - base)
    return {
        "brier": round(score, 4),
        "baseline": round(baseline, 4),
        "skill": round(1 - score / baseline, 4) if baseline else 0.0,
        "better_than_climatology": score < baseline,
    }


def calibration_report(
    probabilities: Sequence[float], outcomes: Sequence[int], *, bins: int = 10
) -> dict[str, Any]:
    if len(probabilities) != len(outcomes) or not probabilities:
        raise PredictError("one probability per outcome is required")
    if bins < 1:
        raise PredictError("at least one bin is required")
    buckets: list[dict[str, Any]] = []
    total = len(probabilities)
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        members = [
            (probability, outcome)
            for probability, outcome in zip(probabilities, outcomes, strict=True)
            if low <= probability < high or (index == bins - 1 and probability == 1.0)
        ]
        if not members:
            continue
        mean_p = sum(p for p, _ in members) / len(members)
        observed = sum(o for _, o in members) / len(members)
        buckets.append(
            {
                "low": round(low, 2),
                "high": round(high, 2),
                "n": len(members),
                "mean_probability": round(mean_p, 3),
                "observed_rate": round(observed, 3),
            }
        )
    ece = sum(bucket["n"] * abs(bucket["mean_probability"] - bucket["observed_rate"]) for bucket in buckets) / total
    return {
        "ece": round(ece, 4),
        "bins": buckets,
        "well_calibrated": ece <= 0.1,
        "n": total,
    }


def detect_anomaly(value: float, history: Sequence[float], *, z: float = 3.0) -> dict[str, Any]:
    if len(history) < 3:
        raise PredictError("anomaly detection needs at least three historical points")
    if z <= 0:
        raise PredictError("the threshold must be positive")
    median = statistics.median(history)
    deviations = [abs(point - median) for point in history]
    mad = statistics.median(deviations)
    if mad == 0:
        spread = statistics.pstdev(history) or 1e-9
        score = (value - median) / spread
        method = "std"
    else:
        score = 0.6745 * (value - median) / mad
        method = "mad"
    return {
        "z": round(score, 3),
        "method": method,
        "anomaly": abs(score) >= z,
        "median": round(median, 4),
        "direction": "high" if score > 0 else ("low" if score < 0 else "flat"),
    }


def reality_check(
    predicted: Mapping[str, float], observed: Mapping[str, float], *, tolerance: float = 0.1
) -> dict[str, Any]:
    if not predicted or not observed:
        raise PredictError("a prediction and an observation are both needed")
    keys = sorted(set(predicted) & set(observed))
    if not keys:
        raise PredictError("the prediction and the observation share no keys")
    per_key = {}
    for key in keys:
        expected = float(predicted[key])
        actual = float(observed[key])
        error = abs(actual - expected)
        scale = max(1.0, abs(expected))
        per_key[key] = {
            "predicted": round(expected, 4),
            "observed": round(actual, 4),
            "error": round(error, 4),
            "relative": round(error / scale, 4),
        }
    mae = sum(entry["error"] for entry in per_key.values()) / len(per_key)
    return {
        "keys": per_key,
        "mae": round(mae, 4),
        "verdict": "close" if mae <= tolerance else "off",
        "tolerance": tolerance,
        "missing": sorted(set(predicted) ^ set(observed)),
    }


def counterfactual(
    series: Sequence[float], *, intervention: float, horizon: int = 1, mode: str = "add"
) -> dict[str, Any]:
    model = linear_forecast(series, horizon=horizon)
    if mode == "add":
        adjusted = [round(value + intervention, 4) for value in model["forecast"]]
    elif mode == "multiply":
        adjusted = [round(value * intervention, 4) for value in model["forecast"]]
    else:
        raise PredictError("mode is 'add' or 'multiply'")
    return {
        "factual": model["forecast"],
        "counterfactual": adjusted,
        "difference": [round(a - b, 4) for a, b in zip(adjusted, model["forecast"], strict=True)],
        "mode": mode,
    }


def fuse(readings: Sequence[Mapping[str, float]]) -> dict[str, Any]:
    """Inverse-variance fusion: a reading that knows its error counts more."""
    if not readings:
        raise PredictError("no readings to fuse")
    weighted = 0.0
    weights = 0.0
    for reading in readings:
        if "value" not in reading or "sigma" not in reading:
            raise PredictError("each reading needs a value and a sigma")
        sigma = float(reading["sigma"])
        if sigma <= 0:
            raise PredictError("sigma must be positive")
        weight = 1.0 / (sigma * sigma)
        weighted += weight * float(reading["value"])
        weights += weight
    return {
        "estimate": round(weighted / weights, 4),
        "sigma": round(math.sqrt(1.0 / weights), 4),
        "readings": len(readings),
    }


def sample_system(samples: int = 5, *, interval_s: float = 0.0) -> list[dict[str, Any]]:
    if samples < 2:
        raise PredictError("at least two samples are needed to see a trend")
    observations = []
    for index in range(samples):
        state = snapshot()
        observations.append(
            {
                "index": index,
                "at_ms": int(time.time() * 1000),
                "load1": float(state["loadavg"][0]),
                "memory_used_pct": float(state["memory"]["used_pct"] or 0.0),
                "processes": int(state["process_count"]),
            }
        )
        if interval_s and index + 1 < samples:
            time.sleep(interval_s)
    return observations


def predict_system(*, samples: int = 6, interval_s: float = 0.0) -> dict[str, Any]:
    """Predict the next reading, then take it and score the prediction."""
    observed = sample_system(samples, interval_s=interval_s)
    history = observed[:-1]
    last = observed[-1]
    predictions = {}
    models = {}
    for key in ("load1", "memory_used_pct"):
        series = [point[key] for point in history]
        model = linear_forecast(series, horizon=1)
        models[key] = model
        predictions[key] = model["forecast"][0]
    check = reality_check(predictions, {key: last[key] for key in predictions})
    return {
        "samples": len(observed),
        "history": observed,
        "models": models,
        "predicted": predictions,
        "observed": {key: last[key] for key in predictions},
        "reality": check,
        "elapsed_ms": round((last["at_ms"] - observed[0]["at_ms"]), 3),
    }
