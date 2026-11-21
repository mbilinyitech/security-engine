"""Payment intents with a mandatory human approval and a gateway that refuses by default.

The service never touches money on its own. It creates a signed intent, requires
a separate approval key, enforces a ceiling, and only then calls a gateway. With
no gateway configured the default is `RefusingGateway`, which raises. Every
settlement writes a balanced double-entry posting.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .audit import AuditLog
from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, PublicIdentity, SigError, now_ms

INTENT_DOMAIN = "omnishield.payments.intent"
APPROVAL_DOMAIN = "omnishield.payments.approval"
INTENT_PROTO = ("payment-intent", 1)
APPROVAL_PROTO = ("payment-approval", 1)


class PaymentError(Exception):
    pass


class Gateway(Protocol):
    def charge(self, intent: dict[str, Any]) -> str: ...


class RefusingGateway:
    def charge(self, intent: dict[str, Any]) -> str:
        raise PaymentError(
            "no payment gateway is configured: refusing to move money"
        )


@dataclass(frozen=True)
class Limits:
    max_amount_cents: int = 100_000
    currencies: tuple[str, ...] = ("USD", "EUR", "TZS", "KES")


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


class PaymentService:
    def __init__(
        self,
        ledger_path: str | os.PathLike[str],
        signer: HybridSigner,
        *,
        limits: Limits | None = None,
        gateway: Gateway | None = None,
        audit: AuditLog | None = None,
    ):
        self.ledger_path = Path(ledger_path)
        self.signer = signer
        self.limits = limits or Limits()
        self.gateway: Gateway = gateway or RefusingGateway()
        self.audit = audit

    def _append(self, record: dict[str, Any]) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.ledger_path, 0o600)

    def postings(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def settled_ids(self) -> set[str]:
        return {record["intent_id"] for record in self.postings()}

    def create(
        self,
        amount_cents: int,
        currency: str,
        payee: str,
        *,
        memo: str = "",
        now: int | None = None,
    ) -> dict[str, Any]:
        if amount_cents <= 0:
            raise PaymentError("amount must be positive")
        if amount_cents > self.limits.max_amount_cents:
            raise PaymentError(
                f"amount {amount_cents} exceeds the ceiling of {self.limits.max_amount_cents}"
            )
        if currency not in self.limits.currencies:
            raise PaymentError(f"currency {currency!r} is not allowed")
        if not payee.strip():
            raise PaymentError("a payment needs a payee")
        issued = now_ms() if now is None else int(now)
        intent = {
            "intent_id": hashlib.sha256(
                f"{amount_cents}|{currency}|{payee}|{memo}|{issued}".encode()
            ).hexdigest()[:20],
            "amount_cents": amount_cents,
            "currency": currency,
            "payee": payee,
            "memo": memo,
            "created_ms": issued,
        }
        envelope = self.signer.sign(
            canonical_bytes(intent),
            domain=INTENT_DOMAIN,
            proto_id=INTENT_PROTO[0],
            proto_version=INTENT_PROTO[1],
            issued_at_ms=issued,
        )
        return {"intent": intent, "envelope": envelope}

    def approve(
        self,
        document: dict[str, Any],
        approver: HybridSigner,
        *,
        approver_name: str,
        verifier: HybridVerifier | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        intent = self._verify_intent(document, verifier or HybridVerifier(self.signer.public_identity))
        if approver.public_identity.key_id == self.signer.public_identity.key_id:
            raise PaymentError("the requester may not approve its own payment")
        if not approver_name.strip():
            raise PaymentError("an approval must name the human who granted it")
        issued = now_ms() if now is None else int(now)
        payload = {
            "intent_id": intent["intent_id"],
            "intent_sha256": _digest(intent),
            "amount_cents": intent["amount_cents"],
            "approver": approver_name,
            "approved_at_ms": issued,
        }
        envelope = approver.sign(
            canonical_bytes(payload),
            domain=APPROVAL_DOMAIN,
            proto_id=APPROVAL_PROTO[0],
            proto_version=APPROVAL_PROTO[1],
            issued_at_ms=issued,
        )
        if self.audit is not None:
            self.audit.append("payments.approve", {"intent_id": intent["intent_id"], "by": approver_name})
        return {"approval": payload, "envelope": envelope}

    def _verify_intent(
        self, document: dict[str, Any], verifier: HybridVerifier, *, now: int | None = None
    ) -> dict[str, Any]:
        intent = dict(document["intent"])
        try:
            verifier.verify(
                document["envelope"],
                canonical_bytes(intent),
                expected_domain=INTENT_DOMAIN,
                expected_proto=INTENT_PROTO,
                now=now,
            )
        except SigError as exc:
            raise PaymentError(f"payment intent is not valid: {exc}") from exc
        return intent

    def settle(
        self,
        document: dict[str, Any],
        approval: dict[str, Any],
        approver_public: PublicIdentity,
        *,
        gateway: Gateway | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        intent = self._verify_intent(document, HybridVerifier(self.signer.public_identity), now=now)
        payload = dict(approval["approval"])
        try:
            HybridVerifier(approver_public).verify(
                approval["envelope"],
                canonical_bytes(payload),
                expected_domain=APPROVAL_DOMAIN,
                expected_proto=APPROVAL_PROTO,
                now=now,
            )
        except SigError as exc:
            raise PaymentError(f"payment approval is not valid: {exc}") from exc
        if payload["intent_sha256"] != _digest(intent):
            raise PaymentError("the approval belongs to a different payment intent")
        if payload["amount_cents"] != intent["amount_cents"]:
            raise PaymentError("the approved amount does not match the intent")
        if intent["intent_id"] in self.settled_ids():
            raise PaymentError("this intent was already settled")
        if intent["amount_cents"] > self.limits.max_amount_cents:
            raise PaymentError("the intent exceeds the configured ceiling")

        receipt = (gateway or self.gateway).charge(intent)
        record = {
            "intent_id": intent["intent_id"],
            "currency": intent["currency"],
            "amount_cents": intent["amount_cents"],
            "debit": {"account": intent["payee"], "amount_cents": intent["amount_cents"]},
            "credit": {"account": "cash", "amount_cents": intent["amount_cents"]},
            "receipt": receipt,
            "settled_ms": now_ms() if now is None else int(now),
            "approved_by": payload["approver"],
        }
        self._append(record)
        if self.audit is not None:
            self.audit.append("payments.settle", {"intent_id": intent["intent_id"], "receipt": receipt})
        return record

    def balance(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for record in self.postings():
            totals[record["debit"]["account"]] = (
                totals.get(record["debit"]["account"], 0) + record["debit"]["amount_cents"]
            )
            totals[record["credit"]["account"]] = (
                totals.get(record["credit"]["account"], 0) - record["credit"]["amount_cents"]
            )
        return totals
