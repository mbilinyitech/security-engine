"""Single-use nonce cache shared by every layer."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .hybrid import ReplayError
from .keystore import write_private_file


class ReplayCache:
    """Rejects a (key_id, nonce) pair the second time it is seen.

    Optional persistence keeps the cache effective across process restarts,
    which matters for signed files and network profiles that live for hours.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None, window_ms: int = 300_000):
        self.path = Path(path) if path is not None else None
        self.window_ms = int(window_ms)
        self._lock = threading.Lock()
        self._entries: dict[str, int] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._entries = {str(k): int(v) for k, v in raw.get("entries", [])}

    def _flush(self) -> None:
        if self.path is None:
            return
        body = json.dumps({"entries": sorted(self._entries.items())}).encode("utf-8")
        write_private_file(self.path, body)

    def _prune(self, now: int) -> None:
        horizon = now - self.window_ms
        stale = [key for key, expiry in self._entries.items() if expiry < horizon]
        for key in stale:
            del self._entries[key]

    def check_and_record(self, key_id: bytes, nonce: bytes, expires_at_ms: int, now: int) -> None:
        token = f"{key_id.hex()}:{nonce.hex()}"
        with self._lock:
            self._prune(now)
            if token in self._entries:
                raise ReplayError("nonce has already been used")
            self._entries[token] = min(int(expires_at_ms), now + self.window_ms)
            self._flush()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
