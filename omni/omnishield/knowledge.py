"""A knowledge store that forgets, repeats and consolidates.

Append-only JSONL, deduplicated by content hash, searched with a small BM25-style
score, decayed on an Ebbinghaus curve, scheduled with spaced repetition, and
consolidated the way sleep does it: merge near-duplicates, prune what never
recurred, and keep the links between terms that co-occurred.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TOKEN = re.compile(r"[a-z0-9']+")
DAY_MS = 86_400_000
STOP = frozenset(
    [
        "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on",
        "with", "as", "by", "that", "this", "be", "are", "was", "were", "from",
        "at", "we", "you", "they", "he", "she", "i", "not", "but", "have", "has",
        "had", "will", "can", "if", "then", "than", "so", "do", "does", "did",
        "its", "their", "our", "your", "there", "here", "what", "which", "who",
        "whom", "when", "where", "why", "how", "all", "any", "both", "each",
        "few", "more", "most", "other", "some", "such", "only", "own", "same",
        "too", "very", "just", "also",
    ]
)


class KnowledgeError(Exception):
    pass


def tokenise(text: str) -> list[str]:
    return [token for token in TOKEN.findall(text.lower()) if token not in STOP and len(token) > 1]


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


@dataclass
class KnowledgeStore:
    path: Path
    items: list[dict[str, Any]] = field(default_factory=list)
    repeats: int = 0

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> KnowledgeStore:
        target = Path(path)
        store = cls(path=target)
        if target.is_file():
            for line in target.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    store.items.append(json.loads(line))
        return store

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = "".join(json.dumps(item, sort_keys=True) + "\n" for item in self.items)
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)

    def add(
        self,
        text: str,
        *,
        source: str,
        title: str = "",
        tags: list[str] | tuple[str, ...] = (),
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        body = _normalise(text)
        if len(body) < 3:
            raise KnowledgeError("the text is too short to learn from")
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        for item in self.items:
            if item["digest"] == digest:
                item["strength"] = int(item.get("strength", 1)) + 1
                item["salience"] = round(min(1.0, float(item.get("salience", 0.5)) + 0.1), 3)
                item["last_seen_ms"] = now
                item["decayed_ms"] = now
                self.repeats += 1
                self._save()
                return {"id": item["id"], "created": False, "salience": item["salience"], "source": source}
        tokens = tokenise(body)
        item = {
            "id": digest[:16],
            "digest": digest,
            "title": _normalise(title) or body[:60],
            "source": source,
            "text": body,
            "tags": sorted({str(tag).lower() for tag in tags}),
            "tokens": len(tokens),
            "created_ms": now,
            "last_seen_ms": now,
            "salience": 0.5,
            "strength": 1,
            "reps": 0,
            "interval_days": 1,
            "due_ms": now + DAY_MS,
        }
        self.items.append(item)
        self._save()
        return {"id": item["id"], "created": True, "salience": 0.5, "source": source}

    def _document_frequency(self) -> dict[str, int]:
        frequencies: dict[str, int] = {}
        for item in self.items:
            for term in set(tokenise(item["text"])):
                frequencies[term] = frequencies.get(term, 0) + 1
        return frequencies

    def search(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        terms = tokenise(query)
        if not terms:
            raise KnowledgeError("the query has no usable terms")
        total = max(1, len(self.items))
        document_frequency = self._document_frequency()
        scored = []
        for item in self.items:
            body = item["text"].lower()
            title = item.get("title", "").lower()
            score = 0.0
            for term in terms:
                tf = body.count(term)
                if not tf:
                    continue
                idf = math.log(1 + total / (1 + document_frequency.get(term, 0)))
                score += tf * idf * (1.0 + 0.5 * title.count(term))
            if score > 0:
                scored.append(
                    {
                        "id": item["id"],
                        "title": item.get("title", ""),
                        "source": item.get("source", ""),
                        "score": round(score * float(item.get("salience", 0.5)), 3),
                        "excerpt": item["text"][:200],
                        "salience": item.get("salience", 0.5),
                    }
                )
        scored.sort(key=lambda entry: -entry["score"])
        return scored[:limit]

    def stats(self) -> dict[str, Any]:
        now = int(time.time() * 1000)
        tags: dict[str, int] = {}
        sources: dict[str, int] = {}
        for item in self.items:
            for tag in item.get("tags", []):
                tags[tag] = tags.get(tag, 0) + 1
            sources[item.get("source", "")] = sources.get(item.get("source", ""), 0) + 1
        saliences = [float(item.get("salience", 0.0)) for item in self.items]
        return {
            "items": len(self.items),
            "repeats": self.repeats,
            "sources": len(sources),
            "tokens": sum(int(item.get("tokens", 0)) for item in self.items),
            "mean_salience": round(sum(saliences) / len(saliences), 3) if saliences else 0.0,
            "due": sum(1 for item in self.items if int(item.get("due_ms", 0)) <= now),
            "top_tags": sorted(tags.items(), key=lambda pair: -pair[1])[:10],
            "oldest_ms": min((int(item["created_ms"]) for item in self.items), default=None),
            "newest_ms": max((int(item["created_ms"]) for item in self.items), default=None),
        }

    def decay(self, *, now_ms: int | None = None, half_life_days: float = 30.0) -> int:
        if half_life_days <= 0:
            raise KnowledgeError("the half-life must be positive")
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        changed = 0
        for item in self.items:
            reference = int(item.get("decayed_ms", item.get("last_seen_ms", now)))
            age_days = max(0.0, (now - reference) / DAY_MS)
            factor = 0.5 ** (age_days / half_life_days)
            before = float(item.get("salience", 0.5))
            after = round(before * factor, 4)
            if after != before:
                item["salience"] = after
                changed += 1
            item["decayed_ms"] = now
        self._save()
        return changed

    def consolidate(
        self, *, now_ms: int | None = None, min_salience: float = 0.05, similarity: float = 0.8
    ) -> dict[str, Any]:
        started = time.perf_counter()
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        merged = 0
        kept: list[dict[str, Any]] = []
        for item in sorted(self.items, key=lambda entry: -float(entry.get("salience", 0.0))):
            tokens = set(tokenise(item["text"]))
            for existing in kept:
                if _jaccard(tokens, set(tokenise(existing["text"]))) >= similarity:
                    existing["strength"] = int(existing.get("strength", 1)) + int(item.get("strength", 1))
                    existing["salience"] = round(min(1.0, float(existing["salience"]) + 0.05), 3)
                    existing["tags"] = sorted(set(existing.get("tags", [])) | set(item.get("tags", [])))
                    merged += 1
                    break
            else:
                kept.append(item)
        pruned = [item for item in kept if float(item.get("salience", 0.0)) < min_salience and int(item.get("strength", 1)) <= 1]
        self.items = [item for item in kept if item not in pruned]
        self._save()
        return {
            "merged": merged,
            "pruned": len(pruned),
            "kept": len(self.items),
            "now_ms": now,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }

    def review(self, *, now_ms: int | None = None, limit: int = 10) -> list[dict[str, Any]]:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        due = [item for item in self.items if int(item.get("due_ms", 0)) <= now]
        due.sort(key=lambda item: (int(item.get("due_ms", 0)), -float(item.get("salience", 0.0))))
        return [
            {"id": item["id"], "title": item.get("title", ""), "due_ms": item["due_ms"], "reps": item.get("reps", 0)}
            for item in due[:limit]
        ]

    def grade(self, item_id: str, grade: int, *, now_ms: int | None = None) -> dict[str, Any]:
        if not 0 <= grade <= 5:
            raise KnowledgeError("the grade runs from 0 to 5")
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        for item in self.items:
            if item["id"] != item_id:
                continue
            if grade >= 3:
                item["reps"] = int(item.get("reps", 0)) + 1
                item["interval_days"] = max(1, round(float(item.get("interval_days", 1)) * 1.8))
            else:
                item["reps"] = 0
                item["interval_days"] = 1
            item["due_ms"] = now + int(item["interval_days"]) * DAY_MS
            item["salience"] = round(
                max(0.0, min(1.0, float(item.get("salience", 0.5)) + 0.05 * grade - 0.05)), 3
            )
            self._save()
            return {
                "id": item["id"],
                "reps": item["reps"],
                "interval_days": item["interval_days"],
                "due_ms": item["due_ms"],
                "salience": item["salience"],
            }
        raise KnowledgeError(f"no item with id {item_id}")

    def links(self, *, top: int = 20) -> list[dict[str, Any]]:
        pairs: dict[tuple[str, str], int] = {}
        for item in self.items:
            counts: dict[str, int] = {}
            for token in tokenise(item["text"]):
                counts[token] = counts.get(token, 0) + 1
            strongest = [term for term, _ in sorted(counts.items(), key=lambda pair: -pair[1])[:5]]
            for index, left in enumerate(strongest):
                for right in strongest[index + 1 :]:
                    key = (left, right) if left < right else (right, left)
                    pairs[key] = pairs.get(key, 0) + 1
        ranked = sorted(pairs.items(), key=lambda pair: -pair[1])[:top]
        return [{"a": a, "b": b, "weight": weight} for (a, b), weight in ranked]
