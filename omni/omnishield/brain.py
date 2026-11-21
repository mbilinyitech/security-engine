"""A daily learning loop shaped like a brain, with the labels kept honest.

What is actually implemented:

* working memory with a 7 (+-2) slot limit and salience-based eviction
* predictive coding: prediction error is measured, not assumed
* intrinsic reward from novelty, competence gain and surprise
* curiosity that ranks gaps in the store and turns them into questions
* a daily cycle: plan, read feeds, store, decay, consolidate, report
* a sleep pass: merge near-duplicates, prune what never recurred, replay

What is not implemented: consciousness, feelings, or a claim that this is a
human brain. The mapping is functional, and each piece is testable.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ingest import ingest_feed
from .knowledge import KnowledgeStore, tokenise


class BrainError(Exception):
    pass


@dataclass
class WorkingMemory:
    capacity: int = 7
    items: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 1 <= self.capacity <= 20:
            raise BrainError("working memory capacity must lie between 1 and 20")

    def add(self, item: Mapping[str, Any], *, salience: float = 0.5) -> dict[str, Any] | None:
        record = dict(item)
        record["salience"] = round(float(salience), 3)
        self.items.append(record)
        if len(self.items) > self.capacity:
            weakest = min(range(len(self.items)), key=lambda index: self.items[index]["salience"])
            return self.items.pop(weakest)
        return None

    def contents(self) -> list[dict[str, Any]]:
        return sorted(self.items, key=lambda item: -item["salience"])

    def clear(self) -> None:
        self.items.clear()


def prediction_error(
    predicted: Mapping[str, float], observed: Mapping[str, float]
) -> dict[str, Any]:
    if not predicted or not observed:
        raise BrainError("both a prediction and an observation are needed")
    keys = set(predicted) | set(observed)
    errors = {key: abs(float(predicted.get(key, 0.0)) - float(observed.get(key, 0.0))) for key in keys}
    mean = sum(errors.values()) / len(errors)
    worst = max(errors, key=lambda key: errors[key])
    return {
        "mean_error": round(mean, 3),
        "max_error": round(errors[worst], 3),
        "worst": worst,
        "surprising": errors[worst] >= 0.5,
        "errors": {key: round(value, 3) for key, value in sorted(errors.items())},
    }


def intrinsic_reward(novelty: float, competence_gain: float, prediction_error_value: float) -> dict[str, Any]:
    for name, value in (
        ("novelty", novelty),
        ("competence_gain", competence_gain),
        ("prediction_error", prediction_error_value),
    ):
        if not 0 <= value <= 1:
            raise BrainError(f"{name} must lie between 0 and 1")
    reward = 0.4 * novelty + 0.35 * competence_gain + 0.25 * prediction_error_value
    return {
        "reward": round(reward, 3),
        "dominant": max(
            {"novelty": novelty, "competence": competence_gain, "surprise": prediction_error_value},
            key=lambda key: {
                "novelty": novelty,
                "competence": competence_gain,
                "surprise": prediction_error_value,
            }[key],
        ),
        "seek": reward >= 0.5,
    }


def curiosity(
    store: KnowledgeStore, *, topics: Sequence[str] | None = None, limit: int = 5
) -> list[dict[str, Any]]:
    """Rank topics by novelty, uncertainty and thin coverage."""
    if limit < 1:
        raise BrainError("the limit must be positive")
    counts: dict[str, int] = {}
    salience: dict[str, list[float]] = {}
    for item in store.items:
        for tag in item.get("tags", []) or ["untagged"]:
            counts[tag] = counts.get(tag, 0) + 1
            salience.setdefault(tag, []).append(float(item.get("salience", 0.0)))
    candidates = list(topics) if topics is not None else sorted(counts)
    ranked = []
    for topic in candidates:
        count = counts.get(topic, 0)
        novelty = 1.0 / (1.0 + count)
        mean_salience = sum(salience.get(topic, [0.0])) / max(1, len(salience.get(topic, [1])))
        uncertainty = 1.0 - min(1.0, mean_salience)
        score = 0.5 * novelty + 0.3 * uncertainty + 0.2 * (1.0 if count == 0 else 0.0)
        ranked.append(
            {
                "topic": topic,
                "items": count,
                "novelty": round(novelty, 3),
                "uncertainty": round(uncertainty, 3),
                "score": round(score, 3),
                "question": f"nini tunachojua kuhusu {topic}?",
            }
        )
    ranked.sort(key=lambda entry: -entry["score"])
    return ranked[:limit]


def sleep(store: KnowledgeStore, *, now_ms: int | None = None) -> dict[str, Any]:
    """Replay, merge, prune and decay in one pass; the nightly maintenance."""
    decayed = store.decay(now_ms=now_ms)
    consolidated = store.consolidate(now_ms=now_ms)
    links = store.links(top=5)
    return {
        "decayed": decayed,
        "merged": consolidated["merged"],
        "pruned": consolidated["pruned"],
        "kept": consolidated["kept"],
        "links": links,
    }


@dataclass
class DailyCycle:
    store: KnowledgeStore
    feeds: Sequence[str] = ()
    allow_private: bool = False
    limit: int = 20
    tags: Sequence[str] = ()
    working_memory: WorkingMemory = field(default_factory=WorkingMemory)

    def run(self, *, now_ms: int | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        before = curiosity(self.store, limit=5)
        results = []
        for feed in self.feeds:
            try:
                result = ingest_feed(
                    feed,
                    self.store,
                    limit=self.limit,
                    allow_private=self.allow_private,
                    tags=list(self.tags),
                )
            except Exception as exc:  # noqa: BLE001 - one broken feed must not stop the day
                result = {"feed": feed, "ok": False, "reason": str(exc), "entries": 0, "added": 0}
            results.append(result)
            if result.get("added"):
                self.working_memory.add({"feed": feed, "added": result["added"]}, salience=0.8)
        maintenance = sleep(self.store, now_ms=now_ms)
        due = self.store.review(now_ms=now_ms, limit=10)
        after = curiosity(self.store, limit=5)
        return {
            "feeds": results,
            "added": sum(int(result.get("added", 0)) for result in results),
            "duplicates": sum(int(result.get("duplicates", 0)) for result in results),
            "failed_feeds": [result["feed"] for result in results if not result.get("ok", True)],
            "maintenance": maintenance,
            "due_reviews": due,
            "questions_before": before,
            "questions_after": after,
            "stats": self.store.stats(),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def write_cycle_log(path: str | Path, document: Mapping[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(document, sort_keys=True) + "\n")
    return target


def run_forever(
    cycle: DailyCycle,
    *,
    interval_s: float,
    log_path: str | Path,
    cycles: int | None = None,
    sleep_fn: Any = time.sleep,
) -> list[dict[str, Any]]:
    """Run the cycle now and then every interval; cron is still the reliable clock."""
    if interval_s <= 0:
        raise BrainError("the interval must be positive")
    completed = []
    while True:
        document = cycle.run()
        document["at_ms"] = int(time.time() * 1000)
        write_cycle_log(log_path, document)
        completed.append(document)
        if cycles is not None and len(completed) >= cycles:
            return completed
        sleep_fn(interval_s)


def knowledge_gap_report(store: KnowledgeStore, *, limit: int = 5) -> dict[str, Any]:
    """What the store is thin on, in words a reader can act on."""
    tokens: dict[str, int] = {}
    for item in store.items:
        for token in set(tokenise(item["text"])):
            tokens[token] = tokens.get(token, 0) + 1
    rare = sorted(tokens.items(), key=lambda pair: pair[1])[:limit]
    return {
        "items": len(store.items),
        "rare_terms": [{"term": term, "items": count} for term, count in rare],
        "questions": curiosity(store, limit=limit),
    }
