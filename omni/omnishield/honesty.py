"""Honesty tooling: score manipulative messages and keep claims tied to evidence.

OmniShield does not generate deception. It detects the patterns that deception
uses, and it refuses to publish a claim that has no evidence attached.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, now_ms

DOMAIN = "omnishield.honesty.claim"
PROTO = ("claim", 1)

SIGNALS: dict[str, tuple[tuple[str, ...], float]] = {
    "urgency": (
        ("haraka", "sasa hivi", "within 24 hours", "immediately", "urgent", "hatari", "last chance"),
        2.0,
    ),
    "authority": (
        ("admin", "police", "bank", "serikali", "support team", "it department", "mamlaka"),
        1.0,
    ),
    "secrecy": (
        ("usimwambie", "do not tell", "keep this secret", "kati yetu", "between us"),
        2.0,
    ),
    "credentials": (
        ("password", "pin", "otp", "nywila", "code ya siri", "verify your account", "thibitisha"),
        2.5,
    ),
    "payment": (
        ("gift card", "bitcoin", "western union", "send money", "tuma pesa", "malipo ya haraka"),
        2.0,
    ),
    "guarantee": (
        ("guaranteed", "hakika 100", "no risk", "double your", "bila shaka"),
        1.5,
    ),
    "isolation": (
        ("do not call", "usipige simu", "don't verify", "usimwulize"),
        1.5,
    ),
}


class HonestyError(Exception):
    pass


def assess(text: str) -> dict[str, Any]:
    lowered = text.lower()
    flags: list[dict[str, Any]] = []
    score = 0.0
    for name, (phrases, weight) in SIGNALS.items():
        hits = [phrase for phrase in phrases if phrase in lowered]
        if hits:
            score += weight
            flags.append({"signal": name, "weight": weight, "hits": hits})
    score = min(score, 10.0)
    verdict = "clean" if score < 2 else ("suspicious" if score < 5 else "deceptive")
    return {
        "score": round(score, 2),
        "verdict": verdict,
        "flags": flags,
        "words": len(re.findall(r"\w+", text)),
    }


def _claim_id(text: str, source: str, created_ms: int) -> str:
    material = f"{text}\x00{source}\x00{created_ms}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


class ClaimLedger:
    """Append-only, signed claims. Only attested claims are publishable."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        signer: HybridSigner,
        *,
        audit: AuditLog | None = None,
    ):
        self.path = Path(path)
        self.signer = signer
        self.audit = audit

    def _append(self, document: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(document, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)

    def _sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = self.signer.sign(
            canonical_bytes(payload),
            domain=DOMAIN,
            proto_id=PROTO[0],
            proto_version=PROTO[1],
            issued_at_ms=payload["created_ms"],
        )
        return {"claim": payload, "envelope": envelope}

    def record(
        self,
        text: str,
        *,
        source: str,
        evidence: Iterable[str | int] = (),
        now: int | None = None,
    ) -> dict[str, Any]:
        if not text.strip():
            raise HonestyError("a claim needs text")
        if not source.strip():
            raise HonestyError("a claim needs a source")
        issued = now_ms() if now is None else int(now)
        payload = {
            "claim_id": _claim_id(text, source, issued),
            "text": text,
            "source": source,
            "evidence": [str(value) for value in evidence],
            "status": "attested" if list(evidence) else "unverified",
            "created_ms": issued,
        }
        document = self._sign(payload)
        self._append(document)
        if self.audit is not None:
            self.audit.append("honesty.claim", {"claim_id": payload["claim_id"]})
        return document

    def verify_claim(
        self,
        document: dict[str, Any],
        verifier: HybridVerifier,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        payload = dict(document["claim"])
        verifier.verify(
            document["envelope"],
            canonical_bytes(payload),
            expected_domain=DOMAIN,
            expected_proto=PROTO,
            now=now,
        )
        return payload

    def attest(
        self,
        document: dict[str, Any],
        evidence: Iterable[str | int],
        *,
        verifier: HybridVerifier,
        now: int | None = None,
    ) -> dict[str, Any]:
        payload = self.verify_claim(document, verifier, now=now)
        values = [str(value) for value in evidence]
        if not values:
            raise HonestyError("attestation needs at least one piece of evidence")
        updated = {
            **payload,
            "evidence": sorted(set(payload["evidence"]) | set(values)),
            "status": "attested",
            "attested_ms": now_ms() if now is None else int(now),
        }
        signed = self._sign(updated)
        self._append(signed)
        return signed

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def publish(self) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for document in self.entries():
            claim = document["claim"]
            latest[claim["claim_id"]] = claim
        return [
            claim
            for claim in latest.values()
            if claim["status"] == "attested" and claim["evidence"]
        ]

    def unverified(self) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for document in self.entries():
            claim = document["claim"]
            latest[claim["claim_id"]] = claim
        return [claim for claim in latest.values() if claim["status"] != "attested"]
