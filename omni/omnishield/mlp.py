"""A two-layer network trained by hand-written backpropagation.

Architecture: 2 inputs -> 4 hidden sigmoid units -> 1 sigmoid output.
The gradients are written out, not autodiffed, so the chain rule is visible:

    y      = sigmoid(W2 h + b2)
    h      = sigmoid(W1 x + b1)
    dL/dy  = y - target
    delta2 = (y - target) * y * (1 - y)
    delta1 = (W2^T delta2) * h * (1 - h)
    W2    -= rate * delta2 h^T
    W1    -= rate * delta1 x^T

It learns XOR, which a single neuron cannot. Every number is measured.
"""

from __future__ import annotations

import csv
import math
import random
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

XOR = [([0.0, 0.0], 0.0), ([0.0, 1.0], 1.0), ([1.0, 0.0], 1.0), ([1.0, 1.0], 0.0)]


class MlpError(Exception):
    pass


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, value))))


def _matrix(rows: int, columns: int, rng: random.Random, scale: float = 1.0) -> list[list[float]]:
    return [[rng.uniform(-scale, scale) for _ in range(columns)] for _ in range(rows)]


class Mlp:
    def __init__(self, *, hidden: int = 4, seed: int = 5) -> None:
        if hidden < 1:
            raise MlpError("the hidden layer needs at least one unit")
        rng = random.Random(seed)
        self.hidden = hidden
        self.w1 = _matrix(hidden, 2, rng)
        self.b1 = [0.0] * hidden
        self.w2 = _matrix(1, hidden, rng)
        self.b2 = [0.0]

    @property
    def parameters(self) -> int:
        return self.hidden * 2 + self.hidden + self.hidden + 1

    def forward(self, inputs: Sequence[float]) -> dict[str, Any]:
        if len(inputs) != 2:
            raise MlpError("the network takes two inputs")
        hidden = [
            _sigmoid(sum(weight * value for weight, value in zip(row, inputs, strict=True)) + bias)
            for row, bias in zip(self.w1, self.b1, strict=True)
        ]
        output = _sigmoid(sum(weight * value for weight, value in zip(self.w2[0], hidden, strict=True)) + self.b2[0])
        return {"hidden": hidden, "output": output}

    def train_step(self, inputs: Sequence[float], target: float, *, rate: float = 0.5) -> float:
        if not 0.0 <= target <= 1.0:
            raise MlpError("the target must be between 0 and 1")
        if rate <= 0.0:
            raise MlpError("the rate must be positive")
        state = self.forward(inputs)
        hidden, output = state["hidden"], state["output"]
        delta2 = (output - target) * output * (1.0 - output)
        for index in range(self.hidden):
            self.w2[0][index] -= rate * delta2 * hidden[index]
        self.b2[0] -= rate * delta2
        for index in range(self.hidden):
            delta1 = delta2 * self.w2[0][index] * hidden[index] * (1.0 - hidden[index])
            for column in range(2):
                self.w1[index][column] -= rate * delta1 * inputs[column]
            self.b1[index] -= rate * delta1
        return 0.5 * (output - target) ** 2

    def predict(self, inputs: Sequence[float]) -> int:
        return 1 if self.forward(inputs)["output"] >= 0.5 else 0

    def accuracy(self, data: Sequence[tuple[list[float], float]]) -> float:
        hits = sum(1 for inputs, target in data if self.predict(inputs) == int(target))
        return round(hits / len(data), 4)


def train(
    data: Sequence[tuple[list[float], float]] = tuple(XOR),
    *,
    epochs: int = 4000,
    rate: float = 0.6,
    hidden: int = 4,
    seed: int = 5,
) -> dict[str, Any]:
    if epochs < 1:
        raise MlpError("epochs must be positive")
    network = Mlp(hidden=hidden, seed=seed)
    before = network.accuracy(data)
    started = time.perf_counter()
    curve = []
    for epoch in range(epochs):
        total = 0.0
        order = list(data)
        random.Random(seed + epoch).shuffle(order)
        for inputs, target in order:
            total += network.train_step(inputs, target, rate=rate)
        curve.append((epoch, total / len(order), network.accuracy(data)))
    elapsed = time.perf_counter() - started
    return {
        "network": network,
        "epochs": epochs,
        "parameters": network.parameters,
        "accuracy_before": before,
        "accuracy_after": network.accuracy(data),
        "loss_first": round(curve[0][1], 6),
        "loss_last": round(curve[-1][1], 6),
        "curve": curve,
        "elapsed_ms": round(elapsed * 1000, 2),
        "epochs_per_s": round(epochs / elapsed) if elapsed else 0,
    }


def demo(*, epochs: int = 4000, out: str | Path | None = None) -> dict[str, Any]:
    result = train(epochs=epochs)
    network = result.pop("network")
    curve = result.pop("curve")
    directory = Path(out) if out else Path("analysis/data/mlp")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "mlp.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["epoch", "loss", "accuracy"])
        for epoch, loss, accuracy in curve:
            writer.writerow([epoch, round(loss, 8), accuracy])
    result["predictions"] = {str(inputs): network.predict(inputs) for inputs, _ in XOR}
    result["csv"] = str(path)
    result["r"] = _run_r(directory)
    return result


def _run_r(directory: Path) -> dict[str, Any] | None:
    import shutil
    import subprocess

    if not shutil.which("Rscript"):
        return None
    script = Path(__file__).resolve().parent.parent / "analysis" / "mlp.R"
    completed = subprocess.run(
        ["Rscript", str(script), str(directory)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return {"ok": completed.returncode == 0, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}
