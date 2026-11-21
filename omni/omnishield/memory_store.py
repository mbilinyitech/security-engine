"""Durable memory: the Rust store plus an on-disk snapshot and an audit chain.

Every mutation writes the full snapshot atomically (0600, temp file + rename)
and then appends a hash-chained audit entry that commits to the new snapshot
digest. `verify()` fails if the database changed without a matching entry, or if
the audit chain itself was edited.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .audit import AuditError, AuditLog
from .canonical import canonical_bytes
from .hybrid import now_ms as current_ms
from .organism import OrganismClient, OrganismError

VERSION = 1


class MemoryStoreError(Exception):
    pass


def parse_vector(text: str) -> list[float]:
    """Accept "1,0,0" or "[1, 0, 0]"."""
    raw = text.strip()
    if not raw:
        raise MemoryStoreError("embedding must not be empty")
    if raw.startswith("["):
        try:
            values = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MemoryStoreError(f"embedding is not valid JSON: {exc}") from exc
    else:
        values = raw.split(",")
    vector: list[float] = []
    for value in values:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise MemoryStoreError(f"embedding contains a non-number: {value!r}") from exc
        if not math.isfinite(number):
            raise MemoryStoreError("embedding must be finite")
        vector.append(number)
    if not vector:
        raise MemoryStoreError("embedding must not be empty")
    return vector


class PersistentMemory:
    def __init__(
        self,
        db: str | os.PathLike[str],
        *,
        audit: str | os.PathLike[str] | None = None,
        key: bytes | None = None,
        binary: str | os.PathLike[str] | None = None,
        capacity: int = 256,
        decay_per_hour: float = 0.02,
        floor: float = 0.05,
    ):
        self.db = Path(db)
        self.audit_path = (
            Path(audit) if audit is not None else self.db.with_name(self.db.name + ".audit.log")
        )
        self.binary = binary
        self.capacity = int(capacity)
        self.decay_per_hour = float(decay_per_hour)
        self.floor = float(floor)
        self._items: list[dict[str, Any]] = []
        try:
            self.audit = AuditLog(self.audit_path, key=key)
        except AuditError as exc:
            raise MemoryStoreError(f"audit log is not trustworthy: {exc}") from exc
        if self.db.exists():
            self._load()

    # -- state ---------------------------------------------------------

    def _document(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "version": VERSION,
            "capacity": self.capacity,
            "decay_per_hour": self.decay_per_hour,
            "floor": self.floor,
            "items": items,
        }

    def digest(self, items: list[dict[str, Any]] | None = None) -> str:
        document = self._document(self._items if items is None else items)
        return hashlib.sha256(canonical_bytes(document)).hexdigest()

    def _load(self) -> None:
        try:
            document = json.loads(self.db.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MemoryStoreError(f"cannot read memory database: {exc}") from exc
        if document.get("version") != VERSION:
            raise MemoryStoreError(f"unsupported memory version {document.get('version')!r}")
        items = document.get("items")
        if not isinstance(items, list):
            raise MemoryStoreError("memory database has no item list")
        self.capacity = int(document.get("capacity", self.capacity))
        self.decay_per_hour = float(document.get("decay_per_hour", self.decay_per_hour))
        self.floor = float(document.get("floor", self.floor))
        if len(items) > self.capacity:
            raise MemoryStoreError("memory database holds more items than its capacity")
        self._items = items

    def _write(self, items: list[dict[str, Any]]) -> None:
        self.db.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._document(items), ensure_ascii=False, sort_keys=True, indent=2)
        handle = None
        tmp_path = None
        try:
            descriptor, tmp_path = tempfile.mkstemp(
                dir=self.db.parent, prefix=".memory-", suffix=".tmp"
            )
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            handle.write(payload + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            handle = None
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.db)
            tmp_path = None
        except OSError as exc:
            raise MemoryStoreError(f"cannot write memory database: {exc}") from exc
        finally:
            if handle is not None:
                handle.close()
            if tmp_path is not None and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.db.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.db.with_name(self.db.name + ".lock")
        with open(lock_path, "a+", encoding="utf-8") as handle:
            try:
                import fcntl
            except ImportError:
                fcntl = None  # type: ignore[assignment]
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield

    # -- core bridge ---------------------------------------------------

    def _session(
        self, method: str, params: dict[str, Any], *, snapshot: bool = False
    ) -> tuple[Any, list[dict[str, Any]] | None]:
        try:
            client = OrganismClient(binary=self.binary)
        except OrganismError as exc:
            raise MemoryStoreError(str(exc)) from exc
        try:
            client.call(
                "memory.init",
                {
                    "capacity": self.capacity,
                    "decay_per_hour": self.decay_per_hour,
                    "floor": self.floor,
                },
            )
            if self._items:
                client.call("memory.restore", {"items": self._items})
            result = client.call(method, params)
            items = client.call("memory.snapshot", {})["items"] if snapshot else None
            return result, items
        except OrganismError as exc:
            raise MemoryStoreError(str(exc)) from exc
        finally:
            client.close()

    def _query(self, method: str, params: dict[str, Any]) -> Any:
        result, _ = self._session(method, params)
        return result

    def _mutate(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock():
            result, items = self._session(method, params, snapshot=True)
            assert items is not None
            self._write(items)
            self._items = items
            self.audit.append(
                method,
                {
                    "snapshot": self.digest(),
                    "params": hashlib.sha256(canonical_bytes(params)).hexdigest(),
                },
            )
            return result

    # -- public operations ---------------------------------------------

    def insert(
        self,
        content: str,
        embedding: list[float] | str,
        *,
        salience: float = 0.5,
        emotion: float = 0.0,
        now: int | None = None,
    ) -> int:
        vector = parse_vector(embedding) if isinstance(embedding, str) else list(embedding)
        result = self._mutate(
            "memory.insert",
            {
                "content": content,
                "embedding": vector,
                "now_ms": current_ms() if now is None else int(now),
                "salience": float(salience),
                "emotion": float(emotion),
            },
        )
        return int(result["id"])

    def search(
        self,
        embedding: list[float] | str,
        *,
        limit: int = 5,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        vector = parse_vector(embedding) if isinstance(embedding, str) else list(embedding)
        return self._query(
            "memory.search",
            {
                "embedding": vector,
                "limit": int(limit),
                "now_ms": current_ms() if now is None else int(now),
            },
        )

    def reinforce(self, identifier: int, *, now: int | None = None) -> None:
        self._mutate(
            "memory.reinforce",
            {"id": int(identifier), "now_ms": current_ms() if now is None else int(now)},
        )

    def forget(self, identifier: int) -> None:
        self._mutate("memory.forget", {"id": int(identifier)})

    def stats(self) -> dict[str, int]:
        return self._query("memory.stats", {})

    def items(self) -> list[dict[str, Any]]:
        return list(self._items)

    # -- integrity -----------------------------------------------------

    def verify(self) -> dict[str, Any]:
        try:
            entries = self.audit.verify()
        except AuditError as exc:
            raise MemoryStoreError(f"audit chain is broken: {exc}") from exc
        trail = list(self.audit.entries())
        digest = self.digest()
        if trail:
            recorded = trail[-1].payload.get("snapshot")
            if recorded != digest:
                raise MemoryStoreError(
                    "database does not match the last audit entry (edited outside the log)"
                )
        elif self._items:
            raise MemoryStoreError("memory exists without an audit trail")
        return {
            "ok": True,
            "entries": entries,
            "items": len(self._items),
            "snapshot": digest,
        }
