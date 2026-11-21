"""One neuron in Python, checked against the Rust one and against R.

A neuron is `sigmoid(sum(x_i * w_i) + bias)`. Training nudges each weight by
`-rate * error * x_i`, where `error = prediction - target`. These are the same
formulas as organism/src/neuron.rs, so the two implementations must agree.
"""

from __future__ import annotations

import csv
import json
import math
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class NeuronError(Exception):
    pass


def dot(inputs: Sequence[float], weights: Sequence[float]) -> float:
    if len(inputs) != len(weights):
        raise NeuronError("length mismatch")
    if not inputs:
        raise NeuronError("the vectors are empty")
    return sum(x * w for x, w in zip(inputs, weights, strict=True))


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, value))))


def forward(inputs: Sequence[float], weights: Sequence[float], bias: float) -> float:
    return sigmoid(dot(inputs, weights) + bias)


def train_step(
    inputs: Sequence[float],
    weights: Sequence[float],
    bias: float,
    target: float,
    rate: float,
) -> dict[str, Any]:
    if not 0.0 <= target <= 1.0:
        raise NeuronError("the target must be between 0 and 1")
    if rate <= 0.0:
        raise NeuronError("the rate must be positive")
    prediction = forward(inputs, weights, bias)
    error = prediction - target
    loss = -target * math.log(max(1e-12, prediction)) - (1 - target) * math.log(max(1e-12, 1 - prediction))
    updated = [w - rate * error * x for x, w in zip(inputs, weights, strict=True)]
    return {
        "weights": updated,
        "bias": bias - rate * error,
        "prediction": prediction,
        "loss": loss,
    }


def bench(dimension: int, repeats: int) -> float:
    if dimension <= 0 or repeats <= 0:
        raise NeuronError("dimension and repeats must be positive")
    inputs = [((index % 97) / 97.0) for index in range(dimension)]
    weights = [((index % 89) / 89.0) - 0.5 for index in range(dimension)]
    started = time.perf_counter()
    total = 0.0
    for _ in range(repeats):
        total += dot(inputs, weights)
    return (time.perf_counter() - started) * 1000.0 / repeats


def _binary() -> Path:
    return Path(__file__).resolve().parent.parent / "organism" / "target" / "release" / "organism"


def rust_forward(inputs: Sequence[float], weights: Sequence[float], bias: float) -> dict[str, Any]:
    executable = _binary()
    if not executable.is_file():
        raise NeuronError("the Rust binary is not built")
    completed = subprocess.run(
        [str(executable), "neuron", "forward", ",".join(map(str, inputs)), ",".join(map(str, weights)), str(bias)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise NeuronError(completed.stderr.strip() or "the Rust neuron failed")
    return json.loads(completed.stdout)


def rust_bench(dimension: int, repeats: int) -> dict[str, Any]:
    executable = _binary()
    if not executable.is_file():
        raise NeuronError("the Rust binary is not built")
    completed = subprocess.run(
        [str(executable), "neuron", "bench", str(dimension), str(repeats)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise NeuronError(completed.stderr.strip() or "the Rust bench failed")
    return json.loads(completed.stdout)


def _run_r(directory: Path) -> dict[str, Any] | None:
    import shutil

    if not shutil.which("Rscript"):
        return None
    script = Path(__file__).resolve().parent.parent / "analysis" / "neuron.R"
    completed = subprocess.run(
        ["Rscript", str(script), str(directory)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return {"ok": completed.returncode == 0, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}


def demo(*, dimension: int = 20_000, repeats: int = 10, out: str | Path | None = None) -> dict[str, Any]:
    inputs = [0.9, -0.4, 0.2, 1.3, -0.7]
    weights = [0.5, -1.0, 2.0, 0.25, -0.5]
    bias = 0.1
    python_prediction = forward(inputs, weights, bias)
    rust = rust_forward(inputs, weights, bias)
    difference = abs(python_prediction - rust["prediction"])

    before = python_prediction
    result = train_step(inputs, weights, bias, 1.0, 0.5)
    after = forward(inputs, result["weights"], result["bias"])

    python_ms = bench(dimension, repeats)
    rust_ms = rust_bench(dimension, repeats)["ms_per_dot"]

    directory = Path(out) if out else Path("analysis/data/neuron")
    directory.mkdir(parents=True, exist_ok=True)
    products = [x * w for x, w in zip(inputs, weights, strict=True)]
    csv_path = directory / "neuron.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["index", "x", "w", "product", "python_dot", "rust_dot"])
        for index, (x, w, product) in enumerate(zip(inputs, weights, products, strict=True)):
            writer.writerow([index, x, w, product, dot(inputs, weights), rust["dot"]])
    r = _run_r(directory)
    return {
        "dot": {"python": dot(inputs, weights), "rust": rust["dot"], "matches": abs(dot(inputs, weights) - rust["dot"]) < 1e-12},
        "forward": {"python": python_prediction, "rust": rust["prediction"], "difference": difference},
        "training": {"before": before, "after": after, "loss": result["loss"]},
        "speed": {
            "dimension": dimension,
            "repeats": repeats,
            "python_ms_per_dot": round(python_ms, 3),
            "rust_ms_per_dot": rust_ms,
            "speedup_x": round(python_ms / rust_ms, 1) if rust_ms else None,
        },
        "r": r,
        "csv": str(csv_path),
    }
