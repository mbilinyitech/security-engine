"""Learn from books and dictionaries, and measure what was learned.

A book is read as paragraphs; a dictionary is read as word/definition pairs.
Both go into the knowledge store, and the strongest terms become Omni roots.
Nothing is scraped: you point it at files you have the right to read.

The report is honest: passages, words, unique terms, new roots, languages seen
and elapsed time. It measures ingestion, not comprehension.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .answer import tokenise
from .language import LanguageError, identify
from .omnilang import Lexicon

PAIR = re.compile(r"^\s*([^:=\t]{1,64})\s*[:=\t]\s*(.{1,600})$")


class CorpusError(Exception):
    pass


def paragraphs(text: str, *, minimum: int = 120) -> list[str]:
    blocks = [re.sub(r"\s+", " ", block).strip() for block in re.split(r"\n\s*\n", text)]
    return [block for block in blocks if len(block) >= minimum]


def read_book(path: str | Path) -> list[str]:
    source = Path(path)
    if not source.is_file():
        raise CorpusError(f"no file at {source}")
    text = source.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise CorpusError(f"{source} is empty")
    blocks = paragraphs(text)
    if not blocks:
        raise CorpusError("no paragraph is long enough to learn from")
    return blocks


def read_dictionary(path: str | Path) -> list[dict[str, str]]:
    source = Path(path)
    if not source.is_file():
        raise CorpusError(f"no file at {source}")
    text = source.read_text(encoding="utf-8", errors="replace")
    entries = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("{"):
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            word = str(document.get("word", "")).strip()
            meaning = str(document.get("definition", document.get("meaning", ""))).strip()
            if word and meaning:
                entries.append({"word": word, "definition": meaning})
            continue
        match = PAIR.match(line)
        if match:
            word, meaning = match.group(1).strip(), match.group(2).strip()
            if word and meaning:
                entries.append({"word": word, "definition": meaning})
    if not entries:
        raise CorpusError("no word/definition pairs were found")
    return entries


def _language_of(passages: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for passage in passages:
        try:
            code = identify(passage)["language"]
        except LanguageError:
            code = "unknown"
        counts[code] = counts.get(code, 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -pair[1]))


def learn_book(store: Any, lexicon: Lexicon, path: str | Path, *, limit: int = 200) -> dict[str, Any]:
    started = time.perf_counter()
    blocks = read_book(path)[:limit]
    new_roots = []
    terms: set[str] = set()
    for block in blocks:
        store.add(block, source=f"book:{Path(path).name}", title=block[:60], tags=["book", "corpus"])
        for term in tokenise(block):
            if len(term) > 3:
                terms.add(term)
    for term in sorted(terms):
        if term not in lexicon.by_concept:
            lexicon.learn(term)
            new_roots.append(term)
    if lexicon.path is not None:
        lexicon.save()
    return {
        "passages": len(blocks),
        "words": sum(len(block.split()) for block in blocks),
        "terms": len(terms),
        "new_roots": len(new_roots),
        "roots": new_roots[:12],
        "lexicon": len(lexicon),
        "languages": _language_of(blocks[:20]),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def learn_dictionary(store: Any, lexicon: Lexicon, path: str | Path, *, limit: int = 5000) -> dict[str, Any]:
    started = time.perf_counter()
    entries = read_dictionary(path)[:limit]
    new_roots = []
    for entry in entries:
        word = entry["word"].lower()
        store.add(
            f"{word}: {entry['definition']}",
            source=f"dictionary:{Path(path).name}",
            title=word,
            tags=["dictionary", "definition"],
        )
        if word not in lexicon.by_concept:
            lexicon.learn(word)
            new_roots.append(word)
    if lexicon.path is not None:
        lexicon.save()
    return {
        "entries": len(entries),
        "new_roots": len(new_roots),
        "roots": new_roots[:12],
        "lexicon": len(lexicon),
        "sample": entries[0] if entries else None,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def learn_directory(store: Any, lexicon: Lexicon, directory: str | Path) -> dict[str, Any]:
    root = Path(directory)
    if not root.is_dir():
        raise CorpusError(f"no directory at {root}")
    books = sorted(root.glob("*.txt")) + sorted(root.glob("*.md"))
    dictionaries = sorted(root.glob("*.dict")) + sorted(root.glob("*.jsonl"))
    report = {"books": [], "dictionaries": [], "errors": []}
    for path in books:
        try:
            report["books"].append({"file": path.name, **learn_book(store, lexicon, path)})
        except CorpusError as error:
            report["errors"].append({"file": path.name, "error": str(error)})
    for path in dictionaries:
        try:
            report["dictionaries"].append({"file": path.name, **learn_dictionary(store, lexicon, path)})
        except CorpusError as error:
            report["errors"].append({"file": path.name, "error": str(error)})
    report["passages"] = sum(row["passages"] for row in report["books"])
    report["entries"] = sum(row["entries"] for row in report["dictionaries"])
    report["lexicon"] = len(lexicon)
    report["store_items"] = len(store.items)
    return report
