"""Hypothetical memory: invented content that can never be recalled as fact.

The agent may hold scenarios. They live in a separate store with their own audit
chain, they are returned only by `simulate()`, and they become real memories only
when `promote()` is given evidence that already exists as fact.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .hybrid import now_ms
from .memory_store import MemoryStoreError, PersistentMemory


class HypotheticalError(Exception):
    pass


class HypotheticalMemory:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        key: bytes | None = None,
        binary: str | os.PathLike[str] | None = None,
        capacity: int = 256,
    ):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.facts = PersistentMemory(
            self.directory / "facts.db", key=key, binary=binary, capacity=capacity
        )
        self.imagined = PersistentMemory(
            self.directory / "imagined.db", key=key, binary=binary, capacity=capacity
        )
        self.provenance_path = self.directory / "provenance.json"
        self._provenance: dict[str, dict[str, Any]] = {}
        if self.provenance_path.exists():
            self._provenance = json.loads(self.provenance_path.read_text(encoding="utf-8"))

    def _fact_ids(self) -> set[int]:
        return {int(item["id"]) for item in self.facts.items()}

    def _save_provenance(self) -> None:
        payload = json.dumps(self._provenance, indent=2, sort_keys=True)
        descriptor, tmp = tempfile.mkstemp(dir=self.directory, prefix=".prov-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.provenance_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def remember(self, content: str, embedding: list[float] | str, *, salience: float = 0.5) -> int:
        return self.facts.insert(content, embedding, salience=salience)

    def imagine(
        self,
        content: str,
        embedding: list[float] | str,
        basis_ids: list[int],
        *,
        salience: float = 0.3,
    ) -> int:
        known = self._fact_ids()
        missing = [identifier for identifier in basis_ids if int(identifier) not in known]
        if not basis_ids:
            raise HypotheticalError("an imagined memory needs at least one real memory as its basis")
        if missing:
            raise HypotheticalError(f"basis memories do not exist: {missing}")
        identifier = self.imagined.insert(
            content, embedding, salience=salience, emotion=0.0, now=now_ms()
        )
        self._provenance[str(identifier)] = {
            "kind": "hypothetical",
            "basis": [int(value) for value in basis_ids],
            "created_ms": now_ms(),
        }
        self._save_provenance()
        return identifier

    def recall(self, embedding: list[float] | str, *, limit: int = 5) -> list[dict[str, Any]]:
        return self.facts.search(embedding, limit=limit)

    def simulate(self, embedding: list[float] | str, *, limit: int = 5) -> list[dict[str, Any]]:
        return self.imagined.search(embedding, limit=limit)

    def provenance(self, identifier: int) -> dict[str, Any]:
        record = self._provenance.get(str(identifier))
        if record is None:
            raise HypotheticalError(f"no provenance for hypothetical {identifier}")
        return record

    def promote(self, identifier: int, evidence_ids: list[int], *, salience: float = 0.6) -> int:
        record = self.provenance(identifier)
        if not evidence_ids:
            raise HypotheticalError("promotion needs evidence from real memory")
        known = self._fact_ids()
        missing = [int(value) for value in evidence_ids if int(value) not in known]
        if missing:
            raise HypotheticalError(f"evidence memories do not exist: {missing}")
        item = next(
            (entry for entry in self.imagined.items() if int(entry["id"]) == int(identifier)), None
        )
        if item is None:
            raise HypotheticalError(f"unknown hypothetical memory {identifier}")
        promoted = self.facts.insert(
            item["content"],
            item["embedding"],
            salience=salience,
            emotion=float(item.get("emotion", 0.0)),
            now=now_ms(),
        )
        self._provenance[str(promoted)] = {
            "kind": "promoted",
            "from": int(identifier),
            "basis": record["basis"],
            "evidence": [int(value) for value in evidence_ids],
            "created_ms": now_ms(),
        }
        self._save_provenance()
        self.imagined.forget(int(identifier))
        return promoted

    def verify(self) -> dict[str, Any]:
        try:
            facts = self.facts.verify()
            imagined = self.imagined.verify()
        except MemoryStoreError as exc:
            raise HypotheticalError(str(exc)) from exc
        return {
            "ok": True,
            "facts": facts["items"],
            "imagined": imagined["items"],
            "provenance": len(self._provenance),
        }
