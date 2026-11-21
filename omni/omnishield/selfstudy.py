"""Teach yourself from what you already stored, and measure whether it stuck.

A lesson takes a passage, picks its strongest terms, invents Omni roots for the
terms it does not know, asks the answer engine a question about the passage and
stores both the lesson and the result. Retention is measured by asking again
afterwards and checking whether the lesson is cited.

This is a curriculum over a local store. It grows vocabulary and recall; it does
not claim understanding.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Sequence
from typing import Any

from .answer import answer, tokenise
from .omnilang import Lexicon

STOP = {"this", "that", "with", "from", "have", "will", "into", "they", "their", "which", "when", "where"}


def top_terms(text: str, limit: int = 6) -> list[str]:
    counts = Counter(term for term in tokenise(text) if term not in STOP and len(term) > 3)
    return [term for term, _ in counts.most_common(limit)]


def lesson(store: Any, lexicon: Lexicon, passage: dict[str, Any]) -> dict[str, Any]:
    text = str(passage.get("text", "")).strip()
    if not text:
        raise ValueError("the passage is empty")
    terms = top_terms(text)
    if not terms:
        raise ValueError("the passage has no usable terms")
    new_roots = []
    for term in terms:
        if term not in lexicon.by_concept:
            lexicon.learn(term)
            new_roots.append(term)
    question = f"what does the text say about {terms[0]}"
    passages = [{"text": item.get("text", ""), "title": item.get("title", ""), "source": item.get("source", "")} for item in store.items]
    result = answer(question, passages)
    cited = any(row["source"] == passage.get("source") for row in result["citations"])
    root_list = ", ".join(f"{term}={lexicon.by_concept[term]}" for term in terms[:4])
    summary = (
        f"Lesson about {terms[0]}: {text[:220]} Terms {root_list}. "
        f"Answer cited {len(result['citations'])} passages at confidence {result['confidence']}."
    )
    store.add(summary, source="selfstudy", title=f"lesson: {terms[0]}", tags=["lesson", "selfstudy"])
    return {
        "terms": terms,
        "new_roots": new_roots,
        "question": question,
        "cited": cited,
        "confidence": result["confidence"],
        "latency_ms": result["latency_ms"],
        "lesson": summary,
    }


def run(
    passages: Sequence[dict[str, Any]],
    store: Any,
    lexicon: Lexicon,
    *,
    rounds: int = 1,
    save_lexicon: bool = True,
) -> dict[str, Any]:
    if not passages:
        raise ValueError("there is nothing to study")
    if rounds < 1:
        raise ValueError("at least one round is required")
    started = time.perf_counter()
    lessons = []
    new_roots: list[str] = []
    for _ in range(rounds):
        for passage in passages:
            record = lesson(store, lexicon, passage)
            lessons.append(record)
            new_roots.extend(record["new_roots"])
    hits = sum(1 for record in lessons if record["cited"])
    if save_lexicon and lexicon.path is not None:
        lexicon.save()
    return {
        "lessons": len(lessons),
        "passages": len(passages),
        "rounds": rounds,
        "new_roots": len(new_roots),
        "roots": new_roots[:12],
        "lexicon": len(lexicon),
        "hit_rate": round(hits / len(lessons), 4),
        "store_items": len(store.items),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }
