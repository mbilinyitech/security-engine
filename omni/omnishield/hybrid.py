"""Hybrid Ed25519 + ML-DSA-44 signature envelopes.

Both signatures must verify. There is no downgrade path: a verifier that cannot
check the post-quantum half rejects the envelope instead of falling back to
Ed25519 alone. Every envelope is bound to a protocol version lock, an issuance
window, and a single-use nonce.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from .canonical import b64d, b64e, canonical_bytes

ALG = "Ed25519+ML-DSA-44"
PREFIX = b"OMNISHIELD/1"
ENVELOPE_VERSION = 1
DEFAULT_TTL_MS = 5 * 60 * 1000
MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000
DEFAULT_SKEW_MS = 120 * 1000

SIGNED_FIELDS = (
    "v",
    "alg",
    "domain",
    "proto_id",
    "proto_version",
    "version_hash",
    "payload_sha256",
    "issued_at_ms",
    "expires_at_ms",
    "nonce",
    "key_id",
)


def now_ms() -> int:
    return int(time.time() * 1000)


def proto_lock(proto_id: str, version: int) -> str:
    """Hash that pins a signature to one exact protocol version."""
    material = f"OMNISHIELD-PROTO/1|{proto_id}|{int(version)}".encode()
    return hashlib.sha256(material).hexdigest()


class SigError(Exception):
    """Base class for every rejection reason."""


class HybridVerifyError(SigError):
    pass


class VersionLockError(SigError):
    pass


class ExpiredError(SigError):
    pass


class ReplayError(SigError):
    pass


class PayloadMismatch(SigError):
    pass


class PolicyError(SigError):
    pass


@dataclass(frozen=True)
class PublicIdentity:
    ed25519_pub: bytes
    mldsa_pub: bytes

    @property
    def key_id(self) -> bytes:
        material = b"OMNISHIELD-KEYID/1" + self.ed25519_pub + self.mldsa_pub
        return hashlib.sha256(material).digest()[:16]

    @property
    def fingerprint(self) -> str:
        return self.key_id.hex()

    def to_dict(self) -> dict[str, str]:
        return {
            "alg": ALG,
            "ed25519": b64e(self.ed25519_pub),
            "mldsa": b64e(self.mldsa_pub),
            "key_id": self.key_id.hex(),
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> PublicIdentity:
        if doc.get("alg") != ALG:
            raise HybridVerifyError(f"unsupported algorithm: {doc.get('alg')!r}")
        identity = cls(b64d(doc["ed25519"]), b64d(doc["mldsa"]))
        if "key_id" in doc and doc["key_id"] != identity.key_id.hex():
            raise HybridVerifyError("public key id does not match key material")
        return identity


@dataclass
class HybridSigner:
    _ed: ed25519.Ed25519PrivateKey
    _ml: mldsa.MLDSA44PrivateKey
    origin: str = "software"
    created_at_ms: int = 0

    @classmethod
    def generate(cls, origin: str = "software") -> HybridSigner:
        return cls(
            _ed=ed25519.Ed25519PrivateKey.generate(),
            _ml=mldsa.MLDSA44PrivateKey.generate(),
            origin=origin,
            created_at_ms=now_ms(),
        )

    @property
    def public_identity(self) -> PublicIdentity:
        return PublicIdentity(
            self._ed.public_key().public_bytes_raw(),
            self._ml.public_key().public_bytes_raw(),
        )

    def sign(
        self,
        payload: bytes,
        *,
        domain: str,
        proto_id: str = "generic",
        proto_version: int = 1,
        ttl_ms: int = DEFAULT_TTL_MS,
        nonce: bytes | None = None,
        issued_at_ms: int | None = None,
        version_hash: str | None = None,
    ) -> dict[str, Any]:
        if ttl_ms <= 0 or ttl_ms > MAX_TTL_MS:
            raise PolicyError(f"ttl_ms must be in (0, {MAX_TTL_MS}]")
        issued = now_ms() if issued_at_ms is None else int(issued_at_ms)
        envelope: dict[str, Any] = {
            "v": ENVELOPE_VERSION,
            "alg": ALG,
            "domain": domain,
            "proto_id": proto_id,
            "proto_version": int(proto_version),
            "version_hash": version_hash or proto_lock(proto_id, proto_version),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "issued_at_ms": issued,
            "expires_at_ms": issued + ttl_ms,
            "nonce": (secrets.token_bytes(16) if nonce is None else nonce).hex(),
            "key_id": self.public_identity.key_id.hex(),
        }
        message = _signed_bytes(envelope)
        envelope["sig_ed25519"] = self._ed.sign(message).hex()
        envelope["sig_mldsa"] = self._ml.sign(message).hex()
        return envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "alg": ALG,
            "ed25519_seed": b64e(self._ed.private_bytes_raw()),
            "mldsa_seed": b64e(self._ml.private_bytes_raw()),
            "origin": self.origin,
            "created_at_ms": self.created_at_ms,
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> HybridSigner:
        if doc.get("alg") != ALG:
            raise HybridVerifyError(f"unsupported algorithm: {doc.get('alg')!r}")
        return cls(
            _ed=ed25519.Ed25519PrivateKey.from_private_bytes(b64d(doc["ed25519_seed"])),
            _ml=mldsa.MLDSA44PrivateKey.from_seed_bytes(b64d(doc["mldsa_seed"])),
            origin=str(doc.get("origin", "software")),
            created_at_ms=int(doc.get("created_at_ms", 0)),
        )


def _signed_bytes(envelope: Mapping[str, Any]) -> bytes:
    body = {field: envelope[field] for field in SIGNED_FIELDS}
    return PREFIX + b"\x00" + canonical_bytes(body)


class HybridVerifier:
    def __init__(self, identity: PublicIdentity):
        self.identity = identity
        self._ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(identity.ed25519_pub)
        self._ml_pub = mldsa.MLDSA44PublicKey.from_public_bytes(identity.mldsa_pub)

    def verify(
        self,
        envelope: Mapping[str, Any],
        payload: bytes | None = None,
        *,
        expected_domain: str | None = None,
        expected_proto: tuple[str, int] | None = None,
        replay: Any = None,
        now: int | None = None,
        max_skew_ms: int = DEFAULT_SKEW_MS,
    ) -> dict[str, Any]:
        env = dict(envelope)
        if env.get("v") != ENVELOPE_VERSION:
            raise HybridVerifyError(f"unsupported envelope version: {env.get('v')!r}")
        if env.get("alg") != ALG:
            raise HybridVerifyError(f"unsupported algorithm: {env.get('alg')!r}")
        if env.get("key_id") != self.identity.key_id.hex():
            raise HybridVerifyError("envelope is signed by a different key")
        if expected_domain is not None and env.get("domain") != expected_domain:
            raise HybridVerifyError(
                f"domain mismatch: expected {expected_domain!r}, got {env.get('domain')!r}"
            )

        try:
            proto_id = str(env["proto_id"])
            proto_version = int(env["proto_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VersionLockError("malformed protocol lock") from exc
        if env.get("version_hash") != proto_lock(proto_id, proto_version):
            raise VersionLockError("protocol version hash does not match locked version")
        if expected_proto is not None and (proto_id, proto_version) != expected_proto:
            raise VersionLockError(
                f"protocol downgrade blocked: expected {expected_proto}, got {(proto_id, proto_version)}"
            )

        current = now_ms() if now is None else int(now)
        issued = int(env["issued_at_ms"])
        expires = int(env["expires_at_ms"])
        if expires - issued > MAX_TTL_MS:
            raise PolicyError("envelope lifetime exceeds policy maximum")
        if issued > current + max_skew_ms:
            raise ExpiredError("envelope is not valid yet")
        if expires < current:
            raise ExpiredError("envelope has expired")

        if payload is not None and hashlib.sha256(payload).hexdigest() != env.get("payload_sha256"):
            raise PayloadMismatch("payload does not match signed digest")

        message = _signed_bytes(env)
        try:
            self._ed_pub.verify(bytes.fromhex(env["sig_ed25519"]), message)
        except (InvalidSignature, ValueError, KeyError) as exc:
            raise HybridVerifyError("Ed25519 half of the signature is invalid") from exc
        try:
            self._ml_pub.verify(bytes.fromhex(env["sig_mldsa"]), message)
        except (InvalidSignature, ValueError, KeyError) as exc:
            raise HybridVerifyError("ML-DSA half of the signature is invalid") from exc

        if replay is not None:
            replay.check_and_record(self.identity.key_id, bytes.fromhex(env["nonce"]), expires, current)
        return env
