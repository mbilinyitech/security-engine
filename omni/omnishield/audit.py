"""Hash-chained audit log.

Each entry commits to the previous entry's hash, so removing, reordering or
editing an entry breaks the chain. With a key, entries are also HMAC'd, which
means an attacker who can write the file still cannot forge a consistent chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .hybrid import now_ms


class AuditError(Exception):
    pass


GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    index: int
    at_ms: int
    kind: str
    payload: dict[str, Any]
    prev: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "at_ms": self.at_ms,
            "kind": self.kind,
            "payload": self.payload,
            "prev": self.prev,
            "hash": self.hash,
        }


def _digest(key: bytes | None, prev: str, body: dict[str, Any]) -> str:
    message = prev.encode("ascii") + b"\x00" + canonical_bytes(body)
    if key is None:
        return hashlib.sha256(message).hexdigest()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class AuditLog:
    """Append-only log. Pass `path` to persist, `key` to authenticate."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        key: bytes | None = None,
    ):
        self.path = Path(path) if path is not None else None
        self._key = key
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self) -> None:
        assert self.path is not None
        entries: list[AuditEntry] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                entries.append(
                    AuditEntry(
                        index=int(raw["index"]),
                        at_ms=int(raw["at_ms"]),
                        kind=str(raw["kind"]),
                        payload=dict(raw["payload"]),
                        prev=str(raw["prev"]),
                        hash=str(raw["hash"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise AuditError(f"corrupt audit line {number}: {exc}") from exc
        self._entries = entries
        self.verify()

    def append(self, kind: str, payload: dict[str, Any], *, at_ms: int | None = None) -> str:
        if not kind or len(kind) > 64:
            raise AuditError("kind must be 1..64 characters")
        if not isinstance(payload, dict):
            raise AuditError("payload must be a mapping")
        with self._lock:
            index = len(self._entries)
            previous = self._entries[-1].hash if self._entries else GENESIS
            stamp = now_ms() if at_ms is None else int(at_ms)
            body = {"index": index, "at_ms": stamp, "kind": kind, "payload": payload}
            digest = _digest(self._key, previous, body)
            entry = AuditEntry(
                index=index,
                at_ms=stamp,
                kind=kind,
                payload=dict(payload),
                prev=previous,
                hash=digest,
            )
            self._entries.append(entry)
            if self.path is not None:
                self._persist(entry)
            return digest

    def _persist(self, entry: AuditEntry) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry.to_dict(), ensure_ascii=False, sort_keys=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        try:
            os.chmod(self.path, 0o600)
        except (AttributeError, OSError):
            pass

    def verify(self) -> int:
        """Return the number of verified entries, or raise `AuditError`."""
        previous = GENESIS
        for position, entry in enumerate(self._entries):
            if entry.index != position:
                raise AuditError(f"entry {position} has index {entry.index}")
            if entry.prev != previous:
                raise AuditError(f"entry {position} does not link to its predecessor")
            body = {
                "index": entry.index,
                "at_ms": entry.at_ms,
                "kind": entry.kind,
                "payload": entry.payload,
            }
            expected = _digest(self._key, previous, body)
            if not hmac.compare_digest(expected, entry.hash):
                raise AuditError(f"entry {position} hash does not match its content")
            previous = entry.hash
        return len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> Iterable[AuditEntry]:
        return tuple(self._entries)

    def tail(self, count: int = 10) -> list[AuditEntry]:
        if count <= 0:
            return []
        return list(self._entries[-count:])

    def head(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS
