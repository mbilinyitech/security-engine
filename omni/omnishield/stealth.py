"""Stealth transport: fixed-size cells, cover traffic, jitter, onion relay.

Two layers, on purpose:

* framing (identical in Rust, ``organism/src/stealth.rs``) turns a payload into
  a fixed-size cell with pseudorandom padding, so the wire never reveals a
  length; cover cells use the same size and the same generator.
* sealing (Python, ChaCha20-Poly1305) encrypts the cell, so an observer sees
  uniform bytes and cannot tell data from cover.

The onion relay encrypts one layer per hop with X25519 + HKDF + ChaCha20-Poly1305;
a relay can open only its own layer and learns only the next hop.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

COVER_MARKER = 0xFFFFFFFF
DEFAULT_CELL = 512
MASK64 = (1 << 64) - 1


class StealthError(Exception):
    pass


class XorShift64:
    """Deterministic padding generator; identical to the Rust implementation."""

    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64 or 0x9E3779B97F4A7C15

    def next_u64(self) -> int:
        value = self.state
        value ^= (value << 13) & MASK64
        value ^= value >> 7
        value ^= (value << 17) & MASK64
        self.state = value
        return (value * 0x2545F4914F6CDD1D) & MASK64

    def fill(self, count: int) -> bytes:
        output = bytearray()
        while len(output) < count:
            output.extend(self.next_u64().to_bytes(8, "little"))
        return bytes(output[:count])


def frame_cell(payload: bytes, *, cell: int = DEFAULT_CELL, seed: int = 0) -> bytes:
    if cell < 8:
        raise StealthError("a cell needs at least 8 bytes")
    if len(payload) > cell - 4:
        raise StealthError(f"payload of {len(payload)} does not fit in {cell - 4} bytes")
    body = len(payload).to_bytes(4, "big") + payload
    padding = XorShift64(seed).fill(cell - len(body))
    return body + padding


def unframe_cell(cell: bytes) -> bytes | None:
    """Return the payload, or None when the cell is cover traffic."""
    if len(cell) < 8:
        raise StealthError("the cell is too short")
    declared = int.from_bytes(cell[:4], "big")
    if declared == COVER_MARKER:
        return None
    if declared > len(cell) - 4:
        raise StealthError("the declared length is larger than the cell")
    return cell[4 : 4 + declared]


def cover_cell(*, cell: int = DEFAULT_CELL, seed: int = 0) -> bytes:
    if cell < 8:
        raise StealthError("a cell needs at least 8 bytes")
    body = COVER_MARKER.to_bytes(4, "big")
    return body + XorShift64(seed).fill(cell - 4)


def jitter_ms(seed: int, index: int, *, base_ms: int = 50, spread_ms: int = 250) -> int:
    if base_ms < 0 or spread_ms < 0:
        raise StealthError("delays cannot be negative")
    generator = XorShift64(seed ^ (index * 0x9E3779B97F4A7C15 & MASK64))
    return base_ms + int(generator.next_u64() % (spread_ms + 1))


def batch(items: Sequence[Any], size: int) -> list[list[Any]]:
    if size < 1:
        raise StealthError("the batch size must be positive")
    return [list(items[index : index + size]) for index in range(0, len(items), size)]


@dataclass
class StealthChannel:
    """Seal frames into uniform wire cells and open them again."""

    key: bytes
    cell: int = DEFAULT_CELL
    seed: int = 0

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise StealthError("the channel key must be 32 bytes")

    def _aead(self) -> ChaCha20Poly1305:
        return ChaCha20Poly1305(self.key)

    def seal(self, payload: bytes, *, cover: int = 0, nonce_source: bytes | None = None) -> list[bytes]:
        if cover < 0:
            raise StealthError("cover cannot be negative")
        frames = [frame_cell(payload, cell=self.cell, seed=self.seed)]
        frames.extend(
            cover_cell(cell=self.cell, seed=self.seed + 1 + index) for index in range(cover)
        )
        wire = []
        for index, frame in enumerate(frames):
            if nonce_source is not None:
                nonce = nonce_source[index * 12 : index * 12 + 12]
                if len(nonce) != 12:
                    raise StealthError("the nonce source is too short")
            else:
                nonce = os.urandom(12)
            wire.append(nonce + self._aead().encrypt(nonce, frame, None))
        return wire

    def open(self, wire: Iterable[bytes]) -> list[bytes]:
        payloads = []
        for sealed in wire:
            if len(sealed) < 12 + 16 + 8:
                raise StealthError("the wire cell is too short")
            nonce, body = sealed[:12], sealed[12:]
            try:
                frame = self._aead().decrypt(nonce, body, None)
            except Exception as exc:  # any AEAD failure is a refusal
                raise StealthError(f"the cell failed authentication: {exc}") from exc
            payload = unframe_cell(frame)
            if payload is not None:
                payloads.append(payload)
        return payloads


def _derive(shared: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"omnishield/onion/1").derive(shared)


def _seal_layer(payload: bytes, public: bytes, *, next_hop: str | None) -> dict[str, Any]:
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
    nonce = os.urandom(12)
    key = _derive(shared, nonce)
    document = json.dumps(
        {"next": next_hop, "payload": payload.hex()}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    box = ChaCha20Poly1305(key).encrypt(nonce, document, None)
    return {
        "v": 1,
        "ephemeral": ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex(),
        "nonce": nonce.hex(),
        "box": box.hex(),
    }


def onion_route(
    hops: Sequence[dict[str, Any]], payload: bytes, *, destination: str | None = None
) -> dict[str, Any]:
    """Wrap payload for hops[0] .. hops[-1]; each hop learns only the next."""
    if not hops:
        raise StealthError("the route is empty")
    for hop in hops:
        if "public" not in hop:
            raise StealthError("every hop needs a public key")
        if not hop.get("address"):
            raise StealthError("every hop needs an address")
    layer: dict[str, Any] | None = None
    for index in range(len(hops) - 1, -1, -1):
        next_hop = hops[index + 1]["address"] if index + 1 < len(hops) else destination
        body = (
            payload
            if layer is None
            else json.dumps(layer, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        layer = _seal_layer(body, hops[index]["public"], next_hop=next_hop)
    assert layer is not None
    return layer


def onion_peel(layer: dict[str, Any], private: bytes) -> dict[str, Any]:
    if layer.get("v") != 1:
        raise StealthError("unknown onion layer version")
    key_pair = X25519PrivateKey.from_private_bytes(private)
    try:
        ephemeral = X25519PublicKey.from_public_bytes(bytes.fromhex(layer["ephemeral"]))
        nonce = bytes.fromhex(layer["nonce"])
        box = bytes.fromhex(layer["box"])
    except (KeyError, ValueError) as exc:
        raise StealthError("the onion layer is malformed") from exc
    shared = key_pair.exchange(ephemeral)
    try:
        plaintext = ChaCha20Poly1305(_derive(shared, nonce)).decrypt(nonce, box, None)
    except Exception as exc:  # any AEAD failure is a refusal
        raise StealthError("this layer is not addressed to this key") from exc
    document = json.loads(plaintext)
    inner = bytes.fromhex(document["payload"])
    if document["next"] is None:
        return {"next": None, "payload": inner, "final": True}
    return {"next": document["next"], "payload": inner, "final": False}


def probe_schedule(
    targets: Sequence[str], *, seed: int = 0, base_ms: int = 100, spread_ms: int = 400
) -> list[dict[str, Any]]:
    """Randomised, rate-limited order for authorised reachability checks."""
    generator = XorShift64(seed)
    ordered = list(targets)
    for index in range(len(ordered) - 1, 0, -1):
        swap = generator.next_u64() % (index + 1)
        ordered[index], ordered[swap] = ordered[swap], ordered[index]
    clock = 0
    schedule = []
    for index, target in enumerate(ordered):
        clock += jitter_ms(seed, index, base_ms=base_ms, spread_ms=spread_ms)
        schedule.append({"index": index, "target": target, "at_ms": clock})
    return schedule


def metrics(cells: Sequence[bytes]) -> dict[str, Any]:
    """What an observer could measure: size spread and byte entropy."""
    if not cells:
        raise StealthError("no cells to measure")
    sizes = [len(cell) for cell in cells]
    sample = b"".join(cells)[:65536]
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / len(sample)
            entropy -= probability * math.log2(probability)
    return {
        "cells": len(cells),
        "sizes": sorted(set(sizes)),
        "size_spread": max(sizes) - min(sizes),
        "entropy_bits_per_byte": round(entropy, 3),
        "uniform": len(set(sizes)) == 1,
    }



def digest(cells: Sequence[bytes]) -> str:
    hasher = hashlib.sha256()
    for cell in cells:
        hasher.update(cell)
    return hasher.hexdigest()
