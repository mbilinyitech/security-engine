"""Protocol 4: deterministic allow-list and behavioural gate.

Nothing loads and nothing is accepted unless it is in a signed manifest. There
is no signature-matching of malware, no heuristics to evade: an artifact is
either listed with a matching SHA-256 or it is refused. The behavioural gate
adds a timing check, because an automated client is usually far more regular
than a human one.
"""
from __future__ import annotations

import hashlib
import math
import os
import statistics
import sys
import types
import unicodedata
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .hybrid import (
    MAX_TTL_MS,
    HybridSigner,
    HybridVerifier,
    SigError,
    now_ms,
)

MANIFEST_DOMAIN = "omnishield.p4.manifest"
MANIFEST_PROTO = ("artifact-manifest", 1)
FRAME_DOMAIN = "omnishield.p4.frame"


class NotAllowed(SigError):
    pass


def _norm(path: str) -> str:
    """Normalise a path key to NFC so macOS (NFD) and Linux (NFC) agree."""
    return unicodedata.normalize("NFC", path)


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> ManifestEntry:
        digest = str(doc["sha256"]).lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise NotAllowed(f"malformed digest for {doc.get('path')!r}")
        return cls(path=str(doc["path"]), sha256=digest, size=int(doc["size"]))


IGNORED_DIRS = frozenset(
    {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".venv", "venv", "node_modules"}
)


def iter_artifacts(root: str | os.PathLike[str]) -> list[Path]:
    """List distributable files under root, skipping build and VCS junk."""
    base = Path(root)
    found = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix == ".pyc":
            continue
        if IGNORED_DIRS & set(path.relative_to(base).parts):
            continue
        found.append(path)
    return found


def hash_file(path: str | os.PathLike[str]) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def build_manifest(
    paths: Iterable[str | os.PathLike[str]],
    signer: HybridSigner,
    *,
    base_dir: str | os.PathLike[str] | None = None,
    now: int | None = None,
    ttl_ms: int = MAX_TTL_MS,
) -> dict[str, Any]:
    root = Path(base_dir).resolve() if base_dir is not None else None
    entries: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        resolved = path.resolve()
        if root is not None:
            try:
                stored = _norm(str(resolved.relative_to(root)))
            except ValueError as exc:
                raise NotAllowed(f"{resolved} is outside base directory {root}") from exc
        else:
            stored = _norm(str(resolved))
        digest, size = hash_file(resolved)
        entries.append({"path": stored, "sha256": digest, "size": size})
    entries.sort(key=lambda item: item["path"])
    issued = now_ms() if now is None else int(now)
    payload = {
        "entries": entries,
        "base_dir": str(root) if root is not None else None,
        "created_at_ms": issued,
    }
    envelope = signer.sign(
        canonical_bytes(payload),
        domain=MANIFEST_DOMAIN,
        proto_id=MANIFEST_PROTO[0],
        proto_version=MANIFEST_PROTO[1],
        ttl_ms=ttl_ms,
        issued_at_ms=issued,
    )
    return {"payload": payload, "envelope": envelope}


def verify_manifest(
    document: Mapping[str, Any],
    verifier: HybridVerifier,
    *,
    base_dir: str | os.PathLike[str] | None = None,
    check_files: bool = True,
    now: int | None = None,
    replay: Any = None,
) -> list[ManifestEntry]:
    payload = dict(document["payload"])
    verifier.verify(
        document["envelope"],
        canonical_bytes(payload),
        expected_domain=MANIFEST_DOMAIN,
        expected_proto=MANIFEST_PROTO,
        now=now,
        replay=replay,
    )
    entries = [ManifestEntry.from_dict(item) for item in payload.get("entries", [])]
    if check_files:
        root = Path(base_dir).resolve() if base_dir is not None else (
            Path(payload["base_dir"]) if payload.get("base_dir") else None
        )
        for entry in entries:
            _verify_entry(entry, root)
    return entries


def _resolve(entry: ManifestEntry, root: Path | None) -> Path:
    path = Path(entry.path)
    if not path.is_absolute():
        if root is None:
            raise NotAllowed(f"{entry.path!r} is relative but no base directory was supplied")
        path = root / path
    if path.is_symlink():
        raise NotAllowed(f"symlink artifacts are not allowed: {path}")
    resolved = path.resolve()
    if root is not None and not resolved.is_relative_to(root):
        raise NotAllowed(f"{entry.path!r} escapes the base directory {root}")
    return resolved


def _verify_entry(entry: ManifestEntry, root: Path | None) -> Path:
    path = _resolve(entry, root)
    if not path.exists():
        raise NotAllowed(f"allow-listed artifact is missing: {path}")
    digest, size = hash_file(path)
    if digest != entry.sha256 or size != entry.size:
        raise NotAllowed(f"artifact does not match the signed manifest: {path}")
    return path


class AllowList:
    """Deny-by-default loader backed by a signed manifest."""

    def __init__(
        self,
        document: Mapping[str, Any],
        verifier: HybridVerifier,
        *,
        base_dir: str | os.PathLike[str] | None = None,
        now: int | None = None,
    ):
        payload = document["payload"]
        root = base_dir if base_dir is not None else payload.get("base_dir")
        self.root = Path(root).resolve() if root else None
        self.entries = verify_manifest(document, verifier, base_dir=root, check_files=False, now=now)
        self._by_path = {_norm(entry.path): entry for entry in self.entries}

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, path: str | os.PathLike[str]) -> ManifestEntry:
        candidate = Path(path)
        if not candidate.is_absolute() and self.root is not None:
            candidate = self.root / candidate
        if self.root is not None:
            try:
                key = str(candidate.resolve().relative_to(self.root))
            except ValueError:
                key = str(candidate)
        else:
            key = str(candidate.resolve())
        entry = self._by_path.get(_norm(key))
        if entry is None:
            raise NotAllowed(f"{path} is not in the signed allow-list")
        return entry

    def verify_path(self, path: str | os.PathLike[str]) -> ManifestEntry:
        entry = self.lookup(path)
        _verify_entry(entry, self.root)
        return entry

    def load_module(self, path: str | os.PathLike[str], name: str | None = None) -> Any:
        """Import a module from the exact bytes whose hash was verified.

        Reading, hashing, and compiling the same buffer closes the
        time-of-check/time-of-use window that a separate verify-then-import
        would leave open.
        """
        entry = self.lookup(path)
        resolved = _resolve(entry, self.root)
        source = resolved.read_bytes()
        if hashlib.sha256(source).hexdigest() != entry.sha256:
            raise NotAllowed(f"artifact changed between verification and load: {resolved}")
        module_name = name or f"omnishield_allowed_{entry.sha256[:16]}"
        module = types.ModuleType(module_name)
        module.__file__ = str(resolved)
        sys.modules[module_name] = module
        try:
            exec(compile(source, str(resolved), "exec"), module.__dict__)  # noqa: S102 - the verified bytes are the point
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
        return module


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    stats: Mapping[str, float]


class InterArrivalGuard:
    """Flags machine-regular request timing.

    A human client jitters. An automated one repeats the same interval, which
    collapses both the coefficient of variation and the timing entropy.
    """

    def __init__(
        self,
        *,
        window: int = 32,
        min_samples: int = 8,
        max_rate_hz: float = 50.0,
        min_cv: float = 0.15,
        min_entropy_bits: float = 1.0,
    ):
        if window < min_samples or min_samples < 2:
            raise ValueError("window must be at least min_samples >= 2")
        self.window = window
        self.min_samples = min_samples
        self.max_rate_hz = max_rate_hz
        self.min_cv = min_cv
        self.min_entropy_bits = min_entropy_bits
        self._deltas: deque[float] = deque(maxlen=window)
        self._last: int | None = None

    def reset(self) -> None:
        self._deltas.clear()
        self._last = None

    def observe(self, now_ms: int) -> Decision:
        if self._last is None:
            self._last = int(now_ms)
            return Decision(True, "warming", {})
        delta = int(now_ms) - self._last
        self._last = int(now_ms)
        if delta < 0:
            self.reset()
            return Decision(False, "clock moved backwards", {})
        self._deltas.append(float(max(delta, 1)))
        if len(self._deltas) < self.min_samples:
            return Decision(True, "warming", {"samples": float(len(self._deltas))})
        stats = self._stats()
        if stats["rate_hz"] > self.max_rate_hz:
            return Decision(False, "request rate exceeds the human ceiling", stats)
        if stats["cv"] < self.min_cv and stats["entropy_bits"] < self.min_entropy_bits:
            return Decision(False, "machine-regular timing", stats)
        return Decision(True, "human-like timing", stats)

    def _stats(self) -> dict[str, float]:
        samples = list(self._deltas)
        mean = statistics.fmean(samples)
        stdev = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        buckets: dict[int, int] = {}
        for value in samples:
            buckets[int(math.log2(value)) if value >= 1 else 0] = (
                buckets.get(int(math.log2(value)) if value >= 1 else 0, 0) + 1
            )
        total = len(samples)
        entropy = -sum((count / total) * math.log2(count / total) for count in buckets.values())
        return {
            "samples": float(total),
            "mean_ms": mean,
            "stdev_ms": stdev,
            "cv": (stdev / mean) if mean else 0.0,
            "entropy_bits": entropy,
            "rate_hz": 1000.0 / mean if mean else float("inf"),
        }


class FrameFilter:
    """Drop every frame that is unsigned, mis-signed, replayed, or bot-timed."""

    def __init__(
        self,
        verifier: HybridVerifier,
        *,
        replay: Any = None,
        guard: InterArrivalGuard | None = None,
        domain: str = FRAME_DOMAIN,
    ):
        self.verifier = verifier
        self.replay = replay
        self.guard = guard
        self.domain = domain

    def accept(
        self,
        envelope: Mapping[str, Any],
        payload: bytes,
        *,
        now: int | None = None,
    ) -> bytes:
        current = now_ms() if now is None else int(now)
        if self.guard is not None:
            decision = self.guard.observe(current)
            if not decision.allow:
                raise NotAllowed(f"behavioural gate: {decision.reason}")
        self.verifier.verify(
            envelope,
            payload,
            expected_domain=self.domain,
            replay=self.replay,
            now=current,
        )
        return payload


def summarise(entries: Sequence[ManifestEntry]) -> str:
    return f"{len(entries)} artifact(s), {sum(entry.size for entry in entries)} bytes"
