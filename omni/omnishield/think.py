"""Deliberate over a question in steps, and show the trace.

The loop is small and checkable:

1. split the question into sub-questions from its strongest terms;
2. retrieve evidence for each one;
3. look for passages that disagree (one negates what another states);
4. answer the whole question and report coverage.

This is structured search and checking. It is not consciousness and it does not
produce beliefs; every claim it makes comes with the passage it came from.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from .answer import Evidence, answer, tokenise

NEGATIONS = {"not", "no", "never", "none", "cannot", "without", "hakuna", "si", "bila"}
CONTRAST = {"but", "however", "although", "lakini", "ila"}


class ThinkError(Exception):
    pass


def _passages(store: Any) -> list[dict[str, Any]]:
    return [
        {"text": item.get("text", ""), "title": item.get("title", ""), "source": item.get("source", "")}
        for item in store.items
    ]


def sub_questions(question: str, *, limit: int = 4) -> list[str]:
    terms = [term for term in tokenise(question) if len(term) > 2][:limit]
    if not terms:
        raise ThinkError("the question has no usable terms")
    return [f"what is said about {term}" for term in terms]


def contradictions(passages: Sequence[dict[str, Any]], *, minimum_shared: int = 2) -> list[dict[str, Any]]:
    found = []
    prepared = []
    for index, passage in enumerate(passages):
        words = set(tokenise(passage["text"]))
        prepared.append((index, words, bool(words & NEGATIONS)))
    for left in range(len(prepared)):
        for right in range(left + 1, len(prepared)):
            left_index, left_words, left_negates = prepared[left]
            right_index, right_words, right_negates = prepared[right]
            shared = left_words & right_words
            if len(shared) >= minimum_shared and left_negates != right_negates:
                found.append(
                    {
                        "left": passages[left_index].get("title") or passages[left_index]["text"][:40],
                        "right": passages[right_index].get("title") or passages[right_index]["text"][:40],
                        "shared": sorted(shared)[:6],
                        "negated_by": "left" if left_negates else "right",
                    }
                )
    return found


def think(question: str, store: Any, *, depth: int = 4, limit: int = 3) -> dict[str, Any]:
    if depth < 1:
        raise ThinkError("depth must be at least one")
    started = time.perf_counter()
    passages = _passages(store)
    if not passages:
        raise ThinkError("the store is empty")
    evidence = Evidence(passages)
    steps = []
    covered = 0
    for sub in sub_questions(question, limit=depth):
        ranked = evidence.bm25(sub)
        if ranked:
            covered += 1
        steps.append(
            {
                "step": "retrieve",
                "question": sub,
                "hits": len(ranked),
                "best": ranked[0]["passage"]["title"] if ranked else None,
                "score": ranked[0]["score"] if ranked else 0.0,
            }
        )
    conflicts = contradictions(passages)
    steps.append({"step": "check", "contradictions": len(conflicts)})
    final = answer(question, passages, limit=limit)
    steps.append({"step": "answer", "citations": len(final["citations"]), "confidence": final["confidence"]})
    return {
        "question": question,
        "answer": final["answer"],
        "citations": final["citations"],
        "confidence": final["confidence"],
        "coverage": round(covered / depth, 4),
        "contradictions": conflicts,
        "steps": steps,
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
    }
