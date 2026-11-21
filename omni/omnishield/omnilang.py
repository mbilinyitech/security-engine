"""Omni: a constructed language the system speaks, writes and parses.

The language is small and regular on purpose. Words are roots built from
consonant-vowel syllables, grammar is subject-verb-object, and meaning is
carried by suffixes:

    -i  plural
    -a  past
    -o  future
    -u  agent (the one who does)
    -e  place

A root is assigned deterministically from the concept, so the same concept
always gets the same word. The lexicon is stored as JSON and grows when the
system learns a concept it did not have.

This is a constructed language with a real parser, not a claim of consciousness.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

CONSONANTS = ["b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z"]
VOWELS = ["a", "e", "i", "o", "u"]
SUFFIXES = {"plural": "n", "past": "m", "future": "f", "agent": "r", "place": "k"}
MARKERS = {"tense_past": "xa", "tense_future": "xo", "question": "ke", "and": "na", "not": "nu"}


class OmniError(Exception):
    pass


def _digest(concept: str) -> int:
    return int(hashlib.sha256(concept.strip().lower().encode()).hexdigest()[:12], 16)


def _syllables(value: int, count: int) -> str:
    letters = []
    for index in range(count):
        letters.append(CONSONANTS[(value >> (index * 5)) % len(CONSONANTS)])
        letters.append(VOWELS[(value >> (index * 5 + 3)) % len(VOWELS)])
    return "".join(letters)


class Lexicon:
    """Concept to root and root to concept, with a deterministic fallback."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path else None
        self.by_concept: dict[str, str] = {}
        self.by_root: dict[str, str] = {}
        if self.path and self.path.is_file():
            document = json.loads(self.path.read_text(encoding="utf-8"))
            self.by_concept = dict(document.get("concepts", {}))
            self.by_root = dict(document.get("roots", {}))

    def __len__(self) -> int:
        return len(self.by_concept)

    def _free_root(self, concept: str) -> str:
        seed = _digest(concept)
        for length in (2, 3, 4):
            candidate = _syllables(seed, length)
            if candidate not in self.by_root:
                return candidate
        counter = 1
        while True:
            candidate = _syllables(seed + counter, 4)
            if candidate not in self.by_root:
                return candidate
            counter += 1

    def learn(self, concept: str) -> str:
        cleaned = concept.strip().lower()
        if not cleaned:
            raise OmniError("a concept needs a name")
        if cleaned in self.by_concept:
            return self.by_concept[cleaned]
        root = self._free_root(cleaned)
        self.by_concept[cleaned] = root
        self.by_root[root] = cleaned
        return root

    def root(self, concept: str) -> str:
        cleaned = concept.strip().lower()
        if cleaned in self.by_concept:
            return self.by_concept[cleaned]
        raise OmniError(f"unknown concept {concept}")

    def concept(self, root: str) -> str:
        cleaned = root.strip().lower()
        if cleaned in self.by_root:
            return self.by_root[cleaned]
        raise OmniError(f"unknown root {root}")

    def save(self) -> Path:
        if not self.path:
            raise OmniError("the lexicon has no path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "version": 1,
            "concepts": dict(sorted(self.by_concept.items())),
            "roots": dict(sorted(self.by_root.items())),
        }
        self.path.write_text(json.dumps(document, indent=1, sort_keys=True), encoding="utf-8")
        return self.path


def word(lexicon: Lexicon, concept: str, *, plural: bool = False, role: str | None = None) -> str:
    root = lexicon.root(concept)
    suffix = ""
    if role in SUFFIXES:
        suffix = SUFFIXES[role]
    elif plural:
        suffix = SUFFIXES["plural"]
    return root + suffix


def speak(
    lexicon: Lexicon,
    subject: str,
    verb: str,
    obj: str | None = None,
    *,
    tense: str = "present",
    plural: bool = False,
    question: bool = False,
) -> str:
    """Render one sentence in Omni."""
    if tense not in {"present", "past", "future"}:
        raise OmniError("tense is present, past or future")
    parts = [word(lexicon, subject, plural=plural)]
    if tense == "past":
        parts.append(MARKERS["tense_past"])
    elif tense == "future":
        parts.append(MARKERS["tense_future"])
    parts.append(word(lexicon, verb))
    if obj:
        parts.append(word(lexicon, obj))
    if question:
        parts.append(MARKERS["question"])
    return " ".join(parts)


def parse(lexicon: Lexicon, sentence: str) -> dict[str, Any]:
    """Read an Omni sentence back into concepts, tense and mood."""
    tokens = [token for token in re.split(r"\s+", sentence.strip().lower()) if token]
    if not tokens:
        raise OmniError("the sentence is empty")
    tense = "present"
    question = False
    concepts: list[dict[str, Any]] = []
    for token in tokens:
        if token == MARKERS["tense_past"]:
            tense = "past"
            continue
        if token == MARKERS["tense_future"]:
            tense = "future"
            continue
        if token == MARKERS["question"]:
            question = True
            continue
        if token in {MARKERS["and"], MARKERS["not"]}:
            concepts.append({"marker": token})
            continue
        role = None
        plural = False
        base = token
        if token[-1] in SUFFIXES.values():
            suffix = token[-1]
            base = token[:-1]
            role = next((name for name, value in SUFFIXES.items() if value == suffix), None)
            plural = role == "plural"
        if base not in lexicon.by_root:
            raise OmniError(f"unknown word {token}")
        concepts.append({"concept": lexicon.by_root[base], "role": role, "plural": plural})
    if len(concepts) < 2:
        raise OmniError("a sentence needs a subject and a verb")
    return {"tense": tense, "question": question, "concepts": concepts}


def gloss(lexicon: Lexicon, sentence: str) -> str:
    parsed = parse(lexicon, sentence)
    pieces = []
    for item in parsed["concepts"]:
        if "marker" in item:
            pieces.append({"na": "and", "nu": "not"}.get(item["marker"], item["marker"]))
            continue
        text = item["concept"]
        if item["plural"]:
            text += "s"
        if item["role"] == "agent":
            text = f"{text} (doer)"
        pieces.append(text)
    tense = "" if parsed["tense"] == "present" else f" [{parsed['tense']}]"
    mood = " [?]" if parsed["question"] else ""
    return " ".join(pieces) + tense + mood


def translate(lexicon: Lexicon, text: str) -> dict[str, Any]:
    """Translate a list of concepts into Omni, learning anything unknown."""
    words = [item for item in re.split(r"[^a-zA-Z]+", text.lower()) if item]
    if not words:
        raise OmniError("there is nothing to translate")
    learned = []
    rendered = []
    for item in words:
        if item in lexicon.by_concept:
            rendered.append(lexicon.by_concept[item])
        else:
            root = lexicon.learn(item)
            learned.append(item)
            rendered.append(root)
    return {"omni": " ".join(rendered), "learned": learned, "words": len(words)}


def seed(lexicon: Lexicon, concepts: Iterable[str]) -> int:
    count = 0
    for concept in concepts:
        before = len(lexicon)
        lexicon.learn(concept)
        count += int(len(lexicon) > before)
    return count
