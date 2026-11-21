"""Learning algorithms that train on data and report what they learned.

Pure Python, no dependencies. Every function returns fitted parameters or
measurements you can check: distances, losses, accuracies, regrets, gradients.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any


class LearningError(Exception):
    pass


def _dot(left: Sequence[float], right: Sequence[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _sigmoid(value: float) -> float:
    if value < -500:
        return 0.0
    if value > 500:
        return 1.0
    return 1.0 / (1.0 + math.exp(-value))


def _distance(left: Sequence[float], right: Sequence[float]) -> float:
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)))


def _log_loss(
    weights: Sequence[float], rows: Sequence[Sequence[float]], labels: Sequence[int]
) -> float:
    total = 0.0
    for row, label in zip(rows, labels):
        probability = min(max(_sigmoid(_dot(weights, row)), 1e-9), 1 - 1e-9)
        total += -(label * math.log(probability) + (1 - label) * math.log(1 - probability))
    return total / max(len(rows), 1)


def _gradient_step(
    weights: Sequence[float],
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    lr: float,
) -> list[float]:
    gradient = [0.0] * len(weights)
    for row, label in zip(rows, labels):
        error = _sigmoid(_dot(weights, row)) - label
        for index, value in enumerate(row):
            gradient[index] += error * value
    return [
        weight - lr * grad / max(len(rows), 1) for weight, grad in zip(weights, gradient)
    ]


def knn_predict(
    train: Sequence[Sequence[float]],
    labels: Sequence[Any],
    point: Sequence[float],
    *,
    k: int = 3,
) -> dict[str, Any]:
    if not train or len(train) != len(labels):
        raise LearningError("training points and labels must line up")
    order = sorted(range(len(train)), key=lambda index: _distance(train[index], point))[:k]
    votes = Counter(labels[index] for index in order)
    label, count = votes.most_common(1)[0]
    return {"label": label, "confidence": round(count / k, 3), "neighbours": order}


def kmeans(
    points: Sequence[Sequence[float]], k: int, *, iterations: int = 50, seed: int = 0
) -> dict[str, Any]:
    if k < 1 or k > len(points):
        raise LearningError("k must be between 1 and the number of points")
    generator = random.Random(seed)
    centroids = [list(points[generator.randrange(len(points))])]
    while len(centroids) < k:
        distances = [
            min(_distance(point, centre) ** 2 for centre in centroids) for point in points
        ]
        total = sum(distances) or 1.0
        target = generator.random() * total
        running = 0.0
        for point, weight in zip(points, distances):
            running += weight
            if running >= target:
                centroids.append(list(point))
                break
        else:
            centroids.append(list(points[-1]))
    assignments = [-1] * len(points)
    for _ in range(iterations):
        updated = [
            min(range(k), key=lambda index: _distance(point, centroids[index]))
            for point in points
        ]
        if updated == assignments:
            break
        assignments = updated
        for index in range(k):
            members = [point for point, owner in zip(points, assignments) if owner == index]
            if members:
                centroids[index] = [
                    sum(member[axis] for member in members) / len(members)
                    for axis in range(len(members[0]))
                ]
    inertia = sum(
        _distance(point, centroids[owner]) ** 2
        for point, owner in zip(points, assignments)
    )
    return {
        "centroids": [[round(value, 4) for value in centre] for centre in centroids],
        "assignments": assignments,
        "inertia": round(inertia, 4),
    }


def q_learning(
    transitions: Sequence[tuple[Any, Any, float, Any, bool]],
    *,
    alpha: float = 0.5,
    gamma: float = 0.9,
    episodes: int = 20,
) -> dict[str, Any]:
    table: dict[tuple[Any, Any], float] = {}
    for _ in range(episodes):
        for state, action, reward, following, done in transitions:
            key = (state, action)
            best_next = 0.0 if done else max(
                (value for (other, _), value in table.items() if other == following),
                default=0.0,
            )
            table[key] = table.get(key, 0.0) + alpha * (
                reward + gamma * best_next - table.get(key, 0.0)
            )
    policy: dict[Any, Any] = {}
    for (state, action), value in table.items():
        if state not in policy or value > table[(state, policy[state])]:
            policy[state] = action
    return {
        "values": {
            f"{state}/{action}": round(value, 4) for (state, action), value in table.items()
        },
        "policy": policy,
    }


def masked_predict(rows: Sequence[Sequence[float]], target: int) -> dict[str, Any]:
    """Self-supervised: hide one column and predict it from the mean of the others."""
    if not rows or not rows[0]:
        raise LearningError("rows are needed")
    features = [
        sum(row[axis] for axis in range(len(row)) if axis != target) / (len(row) - 1)
        for row in rows
    ]
    targets = [row[target] for row in rows]
    mean_x = sum(features) / len(features)
    mean_y = sum(targets) / len(targets)
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(features, targets))
    variance = sum((x - mean_x) ** 2 for x in features) or 1e-9
    slope = covariance / variance
    intercept = mean_y - slope * mean_x
    predictions = [slope * x + intercept for x in features]
    error = sum((p - y) ** 2 for p, y in zip(predictions, targets)) / len(targets)
    return {
        "slope": round(slope, 4),
        "intercept": round(intercept, 4),
        "mse": round(error, 4),
        "predictions": [round(value, 4) for value in predictions],
    }


def behavioural_clone(demonstrations: Sequence[tuple[Sequence[float], Any]]) -> dict[str, Any]:
    if len(demonstrations) < 2:
        raise LearningError("at least two demonstrations are needed")
    correct = 0
    for index, (state, action) in enumerate(demonstrations):
        others = [item for position, item in enumerate(demonstrations) if position != index]
        nearest = min(others, key=lambda item: _distance(state, item[0]))
        correct += int(nearest[1] == action)
    return {
        "policy": "nearest demonstrated state",
        "leave_one_out_accuracy": round(correct / len(demonstrations), 3),
        "examples": len(demonstrations),
    }


def markov_next(sequence: Sequence[Any], state: Any) -> dict[str, Any]:
    if not sequence:
        raise LearningError("a sequence is needed")
    counts: dict[Any, Counter] = {}
    for current, following in pairwise(sequence):
        counts.setdefault(current, Counter())[following] += 1
    distribution = counts.get(state, Counter())
    total = sum(distribution.values())
    if not total:
        return {"next": None, "distribution": {}}
    probabilities = {str(key): round(value / total, 3) for key, value in distribution.items()}
    best = max(distribution, key=distribution.get)
    return {"next": best, "distribution": probabilities, "observed": total}


def epsilon_greedy_bandit(
    means: Sequence[float], *, steps: int = 200, epsilon: float = 0.1, seed: int = 0
) -> dict[str, Any]:
    generator = random.Random(seed)
    totals = [0.0] * len(means)
    counts = [0] * len(means)
    regret = 0.0
    best_mean = max(means)
    for _ in range(steps):
        if generator.random() < epsilon or 0 in counts:
            arm = generator.randrange(len(means))
        else:
            arm = max(range(len(means)), key=lambda index: totals[index] / counts[index])
        reward = 1.0 if generator.random() < means[arm] else 0.0
        totals[arm] += reward
        counts[arm] += 1
        regret += best_mean - means[arm]
    estimates = [
        round(total / count, 3) if count else 0.0 for total, count in zip(totals, counts)
    ]
    return {
        "best_arm": max(range(len(means)), key=lambda index: estimates[index]),
        "estimates": estimates,
        "counts": counts,
        "regret": round(regret, 3),
    }


def fine_tune(
    base: Sequence[float],
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    lr: float = 0.2,
    steps: int = 40,
) -> dict[str, Any]:
    before = _log_loss(base, rows, labels)
    weights = list(base)
    for _ in range(steps):
        weights = _gradient_step(weights, rows, labels, lr)
    after = _log_loss(weights, rows, labels)
    return {
        "weights": [round(value, 4) for value in weights],
        "loss_before": round(before, 4),
        "loss_after": round(after, 4),
        "improved": after < before,
    }


def meta_learning_rate(
    tasks: Sequence[tuple[Sequence[Sequence[float]], Sequence[int]]],
    *,
    rates: Sequence[float] = (0.01, 0.05, 0.1, 0.3, 0.6),
    steps: int = 1,
) -> dict[str, Any]:
    results = []
    for rate in rates:
        losses = []
        for rows, labels in tasks:
            weights = [0.0] * len(rows[0])
            for _ in range(steps):
                weights = _gradient_step(weights, rows, labels, rate)
            losses.append(_log_loss(weights, rows, labels))
        results.append({"rate": rate, "mean_loss": round(sum(losses) / len(losses), 4)})
    best = min(results, key=lambda row: row["mean_loss"])
    return {"best_rate": best["rate"], "results": results}


def continual_update(
    weights: Sequence[float],
    previous: Sequence[float],
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    lr: float = 0.2,
    ewc_lambda: float = 0.5,
) -> dict[str, Any]:
    moved = _gradient_step(weights, rows, labels, lr)
    pull = min(1.0, lr * ewc_lambda)
    updated = [value - pull * (value - old) for value, old in zip(moved, previous)]
    drift = math.sqrt(sum((a - b) ** 2 for a, b in zip(updated, previous)))
    return {
        "weights": [round(value, 4) for value in updated],
        "drift_from_previous": round(drift, 4),
        "loss": round(_log_loss(updated, rows, labels), 4),
    }


def curriculum_order(
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    lr: float = 0.2,
    steps: int = 30,
) -> dict[str, Any]:
    weights = [0.0] * len(rows[0])
    difficulty = []
    for row, label in zip(rows, labels):
        probability = _sigmoid(_dot(weights, row))
        difficulty.append(abs(probability - label))
    order = sorted(range(len(rows)), key=lambda index: difficulty[index])
    easy_rows = [rows[index] for index in order]
    easy_labels = [labels[index] for index in order]
    curriculum = list(weights)
    for _ in range(steps):
        curriculum = _gradient_step(curriculum, easy_rows, easy_labels, lr)
    baseline = list(weights)
    for _ in range(steps):
        baseline = _gradient_step(baseline, rows, labels, lr)
    curriculum_loss = _log_loss(curriculum, rows, labels)
    baseline_loss = _log_loss(baseline, rows, labels)
    return {
        "order": order,
        "curriculum_loss": round(curriculum_loss, 4),
        "baseline_loss": round(baseline_loss, 4),
        "curriculum_better": curriculum_loss < baseline_loss,
    }


def active_select(
    rows: Sequence[Sequence[float]], weights: Sequence[float], *, k: int = 1
) -> dict[str, Any]:
    scored = []
    for index, row in enumerate(rows):
        probability = _sigmoid(_dot(weights, row))
        scored.append((1.0 - abs(2 * probability - 1), index, probability))
    scored.sort(reverse=True)
    chosen = [index for _, index, _ in scored[:k]]
    return {
        "chosen": chosen,
        "uncertainty": [round(value, 4) for value, _, _ in scored[:k]],
    }


def federated_average(clients: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not clients:
        raise LearningError("at least one client is needed")
    total = sum(int(client.get("samples", 1)) for client in clients)
    length = len(clients[0]["weights"])
    averaged = [
        sum(
            float(client["weights"][axis]) * int(client.get("samples", 1))
            for client in clients
        )
        / total
        for axis in range(length)
    ]
    divergence = max(
        math.sqrt(
            sum(
                (float(client["weights"][axis]) - averaged[axis]) ** 2
                for axis in range(length)
            )
        )
        for client in clients
    )
    return {
        "weights": [round(value, 4) for value in averaged],
        "samples": total,
        "max_divergence": round(divergence, 4),
    }


def competitive_update(
    weights: Sequence[Sequence[float]], point: Sequence[float], *, lr: float = 0.1
) -> dict[str, Any]:
    winner = max(range(len(weights)), key=lambda index: _dot(weights[index], point))
    updated = [
        [weight + lr * (value - weight) for weight, value in zip(unit, point)]
        if index == winner
        else list(unit)
        for index, unit in enumerate(weights)
    ]
    return {
        "winner": winner,
        "weights": [[round(value, 4) for value in unit] for unit in updated],
    }


def adversarial_example(
    weights: Sequence[float], point: Sequence[float], label: int, *, epsilon: float = 0.2
) -> dict[str, Any]:
    probability = _sigmoid(_dot(weights, point))
    perturbed = [
        value + epsilon * math.copysign(1.0, (probability - label) * weight)
        for value, weight in zip(point, weights)
    ]
    after = _sigmoid(_dot(weights, perturbed))
    return {
        "clean_probability": round(probability, 4),
        "adversarial": [round(value, 4) for value in perturbed],
        "adversarial_probability": round(after, 4),
        "flipped": int(probability >= 0.5) != int(after >= 0.5),
    }


def triplet_loss(
    anchor: Sequence[float],
    positive: Sequence[float],
    negative: Sequence[float],
    *,
    margin: float = 1.0,
    lr: float = 0.1,
) -> dict[str, Any]:
    to_positive = _distance(anchor, positive) or 1e-9
    to_negative = _distance(anchor, negative) or 1e-9
    before = max(0.0, to_positive - to_negative + margin)
    gradient = [
        (a - p) / to_positive - (a - n) / to_negative
        for a, p, n in zip(anchor, positive, negative)
    ]
    updated = [a - lr * g for a, g in zip(anchor, gradient)]
    after = max(0.0, _distance(updated, positive) - _distance(updated, negative) + margin)
    return {
        "loss_before": round(before, 4),
        "loss_after": round(after, 4),
        "anchor": [round(value, 4) for value in updated],
    }


def naive_bayes(rows: Sequence[Sequence[float]], labels: Sequence[Any]) -> dict[str, Any]:
    classes = sorted(set(labels), key=str)
    stats: dict[Any, dict[str, Any]] = {}
    for label in classes:
        members = [row for row, value in zip(rows, labels) if value == label]
        means = [
            sum(row[axis] for row in members) / len(members) for axis in range(len(members[0]))
        ]
        variances = [
            (sum((row[axis] - means[axis]) ** 2 for row in members) / len(members)) or 1e-6
            for axis in range(len(members[0]))
        ]
        stats[label] = {"mean": means, "var": variances, "prior": len(members) / len(rows)}
    predictions = []
    for row in rows:
        scores = {}
        for label in classes:
            logp = math.log(stats[label]["prior"])
            for axis, value in enumerate(row):
                mean = stats[label]["mean"][axis]
                variance = stats[label]["var"][axis]
                logp += -0.5 * math.log(2 * math.pi * variance) - (value - mean) ** 2 / (
                    2 * variance
                )
            scores[label] = logp
        predictions.append(max(scores, key=scores.get))
    accuracy = sum(int(a == b) for a, b in zip(predictions, labels)) / len(labels)
    return {
        "classes": classes,
        "predictions": predictions,
        "accuracy": round(accuracy, 3),
        "means": {str(k): [round(v, 4) for v in stats[k]["mean"]] for k in classes},
    }


def perceptron(
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    epochs: int = 20,
    lr: float = 0.1,
) -> dict[str, Any]:
    weights = [0.0] * len(rows[0])
    mistakes = 0
    for _ in range(epochs):
        for row, label in zip(rows, labels):
            target = 1 if label else -1
            if target * _dot(weights, row) <= 0:
                weights = [
                    weight + lr * target * value for weight, value in zip(weights, row)
                ]
                mistakes += 1
    predictions = [1 if _dot(weights, row) > 0 else 0 for row in rows]
    accuracy = sum(int(a == b) for a, b in zip(predictions, labels)) / len(labels)
    return {
        "weights": [round(value, 4) for value in weights],
        "accuracy": round(accuracy, 3),
        "mistakes": mistakes,
    }


def prototype_classify(
    support: Mapping[Any, Sequence[Sequence[float]]], query: Sequence[float]
) -> dict[str, Any]:
    prototypes = {}
    for label, examples in support.items():
        prototypes[label] = [
            sum(example[axis] for example in examples) / len(examples)
            for axis in range(len(examples[0]))
        ]
    label = min(prototypes, key=lambda key: _distance(query, prototypes[key]))
    return {
        "label": label,
        "distance": round(_distance(query, prototypes[label]), 4),
        "prototypes": {
            str(key): [round(v, 4) for v in value] for key, value in prototypes.items()
        },
    }


def attribute_classify(
    class_attributes: Mapping[Any, Sequence[float]], attributes: Sequence[float]
) -> dict[str, Any]:
    def cosine(left: Sequence[float], right: Sequence[float]) -> float:
        norm = math.sqrt(_dot(left, left)) * math.sqrt(_dot(right, right))
        return _dot(left, right) / norm if norm else 0.0

    scores = {
        str(label): round(cosine(vector, attributes), 4)
        for label, vector in class_attributes.items()
    }
    return {"label": max(scores, key=scores.get), "scores": scores, "seen_examples": 0}


def one_shot_match(
    example: tuple[Sequence[float], Any], query: Sequence[float], *, threshold: float = 1.0
) -> dict[str, Any]:
    distance = _distance(example[0], query)
    return {
        "label": example[1] if distance <= threshold else None,
        "distance": round(distance, 4),
        "accepted": distance <= threshold,
    }


def shape_reward(
    rewards: Sequence[float], potentials: Sequence[float], *, gamma: float = 0.9
) -> dict[str, Any]:
    if len(potentials) != len(rewards) + 1:
        raise LearningError("potentials need one more entry than rewards")
    shaped = [
        reward + gamma * potentials[index + 1] - potentials[index]
        for index, reward in enumerate(rewards)
    ]
    return {
        "shaped": [round(value, 4) for value in shaped],
        "total_original": round(sum(rewards), 4),
        "total_shaped": round(sum(shaped), 4),
    }


def intrinsic_reward(predictions: Sequence[float], actuals: Sequence[float]) -> dict[str, Any]:
    errors = [abs(prediction - actual) for prediction, actual in zip(predictions, actuals)]
    return {
        "bonuses": [round(value, 4) for value in errors],
        "mean": round(sum(errors) / len(errors), 4) if errors else 0.0,
    }
