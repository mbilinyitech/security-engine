"""Protocol 2: hardware-rooted identity.

A password proves knowledge, and knowledge can be phished, replayed, or handed
to an AI agent. This layer proves possession: the private key lives in the
keystore (TPM when available), every response is bound to a server challenge, a
monotonic counter, and a short validity window, and the hybrid signature covers
all of it. Media credentials use the same key so a capture device can prove what
it produced.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .hybrid import (
    MAX_TTL_MS,
    ExpiredError,
    HybridSigner,
    HybridVerifier,
    HybridVerifyError,
    PublicIdentity,
    ReplayError,
    SigError,
    now_ms,
)
from .keystore import KeyStore, KeyStoreError, write_private_file

AUTH_DOMAIN = "omnishield.p2.auth"
AUTH_PROTO = ("device-auth", 1)
MEDIA_DOMAIN = "omnishield.p2.media"
MEDIA_PROTO = ("media-credential", 1)

MAX_CLOCK_SKEW_MS = 60_000


class IdentityError(SigError):
    pass


class CounterStore:
    """Strictly increasing per-device counter, optionally persisted."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        if self.path is not None and self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._counters = {str(k): int(v) for k, v in raw.items()}

    def _flush(self) -> None:
        if self.path is None:
            return
        write_private_file(self.path, json.dumps(self._counters, sort_keys=True).encode("utf-8"))

    def current(self, device_id: str) -> int:
        with self._lock:
            return self._counters.get(device_id, 0)

    def next(self, device_id: str) -> int:
        with self._lock:
            value = self._counters.get(device_id, 0) + 1
            self._counters[device_id] = value
            self._flush()
            return value

    def record(self, device_id: str, counter: int) -> None:
        with self._lock:
            current = self._counters.get(device_id, 0)
            if counter <= current:
                raise ReplayError(f"counter {counter} does not advance past {current}")
            self._counters[device_id] = counter
            self._flush()


class PinStore:
    """Trust-on-first-use pinning of a named account to one device key.

    Passwords can be shared or phished; a pin makes a key change visible. Once a
    name is pinned, any other key for that name is rejected.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._pins: dict[str, str] = {}
        if self.path is not None and self.path.exists():
            self._pins = {str(k): str(v) for k, v in json.loads(self.path.read_text(encoding="utf-8")).items()}

    def _flush(self) -> None:
        if self.path is not None:
            write_private_file(self.path, json.dumps(self._pins, sort_keys=True).encode("utf-8"))

    def get(self, name: str) -> str | None:
        with self._lock:
            return self._pins.get(name)

    def check_or_pin(self, name: str, key_id: str) -> None:
        with self._lock:
            known = self._pins.get(name)
            if known is None:
                self._pins[name] = key_id
                self._flush()
                return
            if not hmac.compare_digest(known, key_id):
                raise IdentityError(
                    f"pinned key for {name!r} changed: expected {known}, presented {key_id}"
                )


@dataclass
class DeviceIdentity:
    signer: HybridSigner
    origin: str
    name: str = "identity"
    counters: CounterStore | None = None

    def __post_init__(self) -> None:
        if self.counters is None:
            self.counters = CounterStore()

    @classmethod
    def create(
        cls,
        keystore: KeyStore,
        name: str = "identity",
        counters: CounterStore | None = None,
    ) -> DeviceIdentity:
        signer = HybridSigner.generate(origin=keystore.origin)
        identity = cls(signer=signer, origin=keystore.origin, name=name, counters=counters)
        identity.save(keystore)
        return identity

    @classmethod
    def load(
        cls,
        keystore: KeyStore,
        name: str = "identity",
        counters: CounterStore | None = None,
    ) -> DeviceIdentity:
        try:
            blob = keystore.load(name)
        except KeyStoreError as exc:
            raise IdentityError(str(exc)) from exc
        doc = json.loads(blob.decode("utf-8"))
        signer = HybridSigner.from_dict(doc["signer"])
        return cls(
            signer=signer,
            origin=str(doc.get("origin", signer.origin)),
            name=name,
            counters=counters,
        )

    def save(self, keystore: KeyStore) -> None:
        document = {"signer": self.signer.to_dict(), "origin": self.origin}
        keystore.save(self.name, json.dumps(document, sort_keys=True).encode("utf-8"))

    @property
    def identity(self) -> PublicIdentity:
        return self.signer.public_identity

    @property
    def device_id(self) -> str:
        return self.identity.key_id.hex()

    def public_document(self) -> dict[str, Any]:
        return {**self.identity.to_dict(), "origin": self.origin}

    def respond(
        self,
        server_nonce: bytes,
        context: str,
        *,
        now: int | None = None,
        ttl_ms: int = 60_000,
    ) -> dict[str, Any]:
        if not server_nonce:
            raise IdentityError("server challenge must not be empty")
        issued = now_ms() if now is None else int(now)
        payload = {
            "device_id": self.device_id,
            "key_origin": self.origin,
            "server_nonce": server_nonce.hex(),
            "client_nonce": secrets.token_bytes(32).hex(),
            "context": context,
            "counter": self.counters.next(self.device_id),
            "device_time_ms": issued,
        }
        envelope = self.signer.sign(
            canonical_bytes(payload),
            domain=AUTH_DOMAIN,
            proto_id=AUTH_PROTO[0],
            proto_version=AUTH_PROTO[1],
            ttl_ms=ttl_ms,
            issued_at_ms=issued,
        )
        return {"payload": payload, "envelope": envelope}


def verify_response(
    document: Mapping[str, Any],
    identity: PublicIdentity,
    *,
    server_nonce: bytes,
    expected_context: str | None = None,
    counters: CounterStore | None = None,
    pins: PinStore | None = None,
    pin_name: str | None = None,
    now: int | None = None,
    max_skew_ms: int = MAX_CLOCK_SKEW_MS,
    replay: Any = None,
) -> dict[str, Any]:
    payload = dict(document["payload"])
    if payload.get("device_id") != identity.key_id.hex():
        raise HybridVerifyError("response is bound to a different device key")
    try:
        presented = bytes.fromhex(str(payload["server_nonce"]))
    except (KeyError, ValueError) as exc:
        raise HybridVerifyError("malformed server challenge in response") from exc
    if not hmac.compare_digest(presented, server_nonce):
        raise HybridVerifyError("response does not answer this challenge")
    if expected_context is not None and payload.get("context") != expected_context:
        raise HybridVerifyError("context binding mismatch")

    HybridVerifier(identity).verify(
        document["envelope"],
        canonical_bytes(payload),
        expected_domain=AUTH_DOMAIN,
        expected_proto=AUTH_PROTO,
        now=now,
        replay=replay,
    )

    current = now_ms() if now is None else int(now)
    try:
        device_time = int(payload["device_time_ms"])
        counter = int(payload["counter"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HybridVerifyError("malformed response payload") from exc
    if abs(current - device_time) > max_skew_ms:
        raise ExpiredError("device clock is outside the accepted skew window")
    if pins is not None:
        if pin_name is None:
            raise IdentityError("pin_name is required when a PinStore is supplied")
        pins.check_or_pin(pin_name, identity.key_id.hex())
    if counters is not None:
        counters.record(payload["device_id"], counter)
    return payload


def sign_media(
    path: str | os.PathLike[str],
    identity: DeviceIdentity,
    *,
    capture_origin: str = "unknown",
    now: int | None = None,
    ttl_ms: int = MAX_TTL_MS,
) -> dict[str, Any]:
    file_path = Path(path)
    digest, size = _hash_file(file_path)
    issued = now_ms() if now is None else int(now)
    payload = {
        "filename": file_path.name,
        "sha256": digest,
        "size": size,
        "capture_origin": capture_origin,
        "key_origin": identity.origin,
        "device_id": identity.device_id,
        "signed_at_ms": issued,
    }
    envelope = identity.signer.sign(
        canonical_bytes(payload),
        domain=MEDIA_DOMAIN,
        proto_id=MEDIA_PROTO[0],
        proto_version=MEDIA_PROTO[1],
        ttl_ms=ttl_ms,
        issued_at_ms=issued,
    )
    return {"payload": payload, "envelope": envelope}


def verify_media(
    path: str | os.PathLike[str],
    document: Mapping[str, Any],
    identity: PublicIdentity,
    *,
    now: int | None = None,
    require_fresh_within_ms: int | None = None,
) -> dict[str, Any]:
    """Validate a content credential.

    Signature validity is checked as of the signing time, so a credential keeps
    proving provenance after its issuance window closes. Pass
    require_fresh_within_ms to also demand recent capture.
    """
    payload = dict(document["payload"])
    if payload.get("device_id") != identity.key_id.hex():
        raise HybridVerifyError("media credential names a different device")
    signed_at = int(payload.get("signed_at_ms", 0))
    HybridVerifier(identity).verify(
        document["envelope"],
        canonical_bytes(payload),
        expected_domain=MEDIA_DOMAIN,
        expected_proto=MEDIA_PROTO,
        now=signed_at if now is None else now,
    )
    digest, size = _hash_file(Path(path))
    if digest != payload.get("sha256") or size != int(payload.get("size", -1)):
        raise HybridVerifyError("media file does not match its credential")
    if require_fresh_within_ms is not None:
        current = now_ms() if now is None else int(now)
        if current - signed_at > require_fresh_within_ms:
            raise ExpiredError("media credential is older than the freshness policy allows")
    return payload


def is_hardware_rooted(payload: Mapping[str, Any]) -> bool:
    return payload.get("key_origin") == "tpm2"


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
