"""Machine-to-machine communication with every message signed.

Signed frames over TCP, signed beacons over UDP, a trust-on-first-use device
registry that refuses key changes, reachability probes, an ARP and listening
port inventory, RFC 5424 syslog and SNTP time checks.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, PublicIdentity, SigError, now_ms

DOMAIN = "omnishield.net.message"
BEACON_DOMAIN = "omnishield.net.beacon"
MESSAGE_PROTO = ("message", 1)
BEACON_PROTO = ("beacon", 1)


class FederationError(Exception):
    pass


class ReplayWindow:
    """Nonces are remembered for a bounded time; a repeat is refused."""

    def __init__(self, ttl_ms: int = 300_000) -> None:
        self.ttl_ms = ttl_ms
        self.seen: dict[str, int] = {}

    def check(self, nonce: str, now: int) -> None:
        cutoff = now - self.ttl_ms
        for key in [key for key, at in self.seen.items() if at < cutoff]:
            del self.seen[key]
        if nonce in self.seen:
            raise FederationError("replayed message")
        self.seen[nonce] = now


def seal_message(
    payload: Mapping[str, Any],
    *,
    kind: str,
    signer: HybridSigner,
    sequence: int = 0,
    ttl_ms: int = 60_000,
    now: int | None = None,
) -> dict[str, Any]:
    issued = now_ms() if now is None else int(now)
    unsigned = {
        "proto": "omnishield.net.message",
        "version": 1,
        "kind": kind,
        "sender": signer.public_identity.key_id.hex(),
        "sequence": int(sequence),
        "sent_at_ms": issued,
        "nonce": secrets.token_hex(16),
        "payload": dict(payload),
    }
    envelope = signer.sign(
        canonical_bytes(unsigned),
        domain=DOMAIN,
        proto_id=MESSAGE_PROTO[0],
        proto_version=MESSAGE_PROTO[1],
        issued_at_ms=issued,
        ttl_ms=ttl_ms,
    )
    return {"message": unsigned, "envelope": envelope}


def open_message(
    document: Mapping[str, Any],
    *,
    verifier: HybridVerifier,
    replay: ReplayWindow,
    now: int | None = None,
    max_skew_ms: int = 120_000,
) -> dict[str, Any]:
    if "message" not in document or "envelope" not in document:
        raise FederationError("the frame has no message or no signature")
    unsigned = dict(document["message"])
    if unsigned.get("proto") != "omnishield.net.message":
        raise FederationError("unknown message protocol")
    try:
        verifier.verify(
            document["envelope"],
            canonical_bytes(unsigned),
            expected_domain=DOMAIN,
            expected_proto=MESSAGE_PROTO,
            now=now,
        )
    except SigError as exc:
        raise FederationError(f"the message signature is not valid: {exc}") from exc
    current = now_ms() if now is None else int(now)
    if abs(current - int(unsigned["sent_at_ms"])) > max_skew_ms:
        raise FederationError("the message is outside the accepted time window")
    if unsigned["sender"] != verifier.identity.key_id.hex():
        raise FederationError("the sender does not match the pinned identity")
    replay.check(str(unsigned["nonce"]), current)
    return {
        "kind": unsigned["kind"],
        "payload": unsigned["payload"],
        "sender": unsigned["sender"],
        "sequence": unsigned["sequence"],
        "sent_at_ms": unsigned["sent_at_ms"],
    }


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = connection.recv(count - len(buffer))
        if not chunk:
            raise FederationError("the peer closed the connection")
        buffer += chunk
    return buffer


def send_message(connection: socket.socket, document: Mapping[str, Any]) -> int:
    body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    connection.sendall(struct.pack(">I", len(body)) + body)
    return len(body)


def receive_message(
    connection: socket.socket,
    *,
    verifier: HybridVerifier,
    replay: ReplayWindow,
    max_bytes: int = 1_000_000,
) -> dict[str, Any]:
    length = struct.unpack(">I", _recv_exact(connection, 4))[0]
    if length > max_bytes:
        raise FederationError("the frame is larger than the limit")
    document = json.loads(_recv_exact(connection, length))
    return open_message(document, verifier=verifier, replay=replay)


def beacon_document(
    device_id: str,
    *,
    signer: HybridSigner,
    capabilities: Iterable[str] = (),
    port: int = 0,
    ttl_s: int = 60,
    now: int | None = None,
) -> dict[str, Any]:
    if not device_id.strip():
        raise FederationError("a beacon needs a device id")
    issued = now_ms() if now is None else int(now)
    unsigned = {
        "proto": "omnishield.net.beacon",
        "version": 1,
        "device_id": device_id,
        "public": signer.public_identity.to_dict(),
        "capabilities": sorted(set(capabilities)),
        "port": int(port),
        "issued_at_ms": issued,
        "expires_at_ms": issued + ttl_s * 1000,
        "nonce": secrets.token_hex(12),
    }
    envelope = signer.sign(
        canonical_bytes(unsigned),
        domain=BEACON_DOMAIN,
        proto_id=BEACON_PROTO[0],
        proto_version=BEACON_PROTO[1],
        issued_at_ms=issued,
        ttl_ms=ttl_s * 1000,
    )
    return {"beacon": unsigned, "envelope": envelope}


def verify_beacon(document: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
    if "beacon" not in document or "envelope" not in document:
        raise FederationError("the beacon has no signature")
    unsigned = dict(document["beacon"])
    try:
        identity = PublicIdentity.from_dict(unsigned["public"])
    except Exception as exc:  # any malformed key is a refusal
        raise FederationError(f"the beacon key is malformed: {exc}") from exc
    try:
        HybridVerifier(identity).verify(
            document["envelope"],
            canonical_bytes(unsigned),
            expected_domain=BEACON_DOMAIN,
            expected_proto=BEACON_PROTO,
            now=now,
        )
    except SigError as exc:
        raise FederationError(f"the beacon signature is not valid: {exc}") from exc
    current = now_ms() if now is None else int(now)
    if current > int(unsigned["expires_at_ms"]):
        raise FederationError("the beacon has expired")
    if unsigned["device_id"] != unsigned["public"]["key_id"]:
        raise FederationError("the device id must be the key fingerprint")
    return {
        "device_id": unsigned["device_id"],
        "identity": identity,
        "capabilities": list(unsigned["capabilities"]),
        "port": int(unsigned["port"]),
        "expires_at_ms": int(unsigned["expires_at_ms"]),
    }


def broadcast_beacon(
    port: int, document: Mapping[str, Any], *, address: str = "255.255.255.255"
) -> int:
    body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sender.sendto(body, (address, port))


def listen_beacons(
    port: int, *, timeout: float = 1.0, host: str = "0.0.0.0", limit: int = 64
) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver.bind((host, port))
        receiver.settimeout(timeout)
        for _ in range(limit):
            try:
                body, address = receiver.recvfrom(65_535)
            except TimeoutError:
                break
            try:
                document = json.loads(body)
                document["_from"] = address[0]
                documents.append(document)
            except json.JSONDecodeError:
                continue
    return documents


@dataclass
class DeviceRegistry:
    """Trust on first use: a device may enrol once, and never change its key."""

    path: Path | None = None
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            if self.path.is_file():
                self.load()

    def pin(
        self,
        device_id: str,
        public: PublicIdentity,
        *,
        capabilities: Iterable[str] = (),
        now: int | None = None,
        ttl_s: int = 300,
    ) -> dict[str, Any]:
        current = now_ms() if now is None else int(now)
        existing = self.devices.get(device_id)
        if existing is not None and existing["key_id"] != public.key_id.hex():
            raise FederationError("the device presented a different key")
        record = {
            "device_id": device_id,
            "key_id": public.key_id.hex(),
            "public": public.to_dict(),
            "capabilities": sorted(set(capabilities)),
            "first_seen_ms": existing["first_seen_ms"] if existing else current,
            "last_seen_ms": current,
            "expires_at_ms": current + ttl_s * 1000,
        }
        self.devices[device_id] = record
        self.save()
        return record

    def touch(self, device_id: str, *, now: int | None = None, ttl_s: int = 300) -> dict[str, Any]:
        if device_id not in self.devices:
            raise FederationError(f"unknown device {device_id!r}")
        current = now_ms() if now is None else int(now)
        self.devices[device_id]["last_seen_ms"] = current
        self.devices[device_id]["expires_at_ms"] = current + ttl_s * 1000
        self.save()
        return self.devices[device_id]

    def lookup(self, device_id: str) -> dict[str, Any] | None:
        return self.devices.get(device_id)

    def stale(self, *, now: int | None = None) -> list[str]:
        current = now_ms() if now is None else int(now)
        return sorted(
            device_id
            for device_id, record in self.devices.items()
            if int(record["expires_at_ms"]) < current
        )

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"devices": self.devices}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.path, 0o600)

    def load(self) -> None:
        if self.path is None or not self.path.is_file():
            return
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.devices = dict(document.get("devices", {}))


def probe(host: str, port: int, *, timeout: float = 1.0) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
            return {"open": True, "ms": round(elapsed, 2), "host": host, "port": port}
    except OSError as exc:
        return {
            "open": False,
            "ms": None,
            "host": host,
            "port": port,
            "reason": exc.strerror or type(exc).__name__,
        }


def neighbours(path: str | os.PathLike[str] = "/proc/net/arp") -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        return {"available": False, "entries": [], "reason": "no ARP table on this system"}
    entries = []
    for line in source.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        address, _hardware_type, flags, mac, _mask, device = parts[:6]
        entries.append(
            {
                "ip": address,
                "mac": mac,
                "device": device,
                "flags": flags,
                "complete": flags != "0x0",
            }
        )
    return {"available": True, "entries": entries}


def listening_ports(
    path: str | os.PathLike[str] = "/proc/net/tcp",
) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        return {"available": False, "ports": [], "reason": "no /proc/net/tcp on this system"}
    found: dict[int, set[str]] = {}
    for line in source.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        address, port_hex = parts[1].split(":")
        try:
            port = int(port_hex, 16)
            octets = [str(int(address[index : index + 2], 16)) for index in (6, 4, 2, 0)]
        except ValueError:
            continue
        found.setdefault(port, set()).add(".".join(octets))
    return {
        "available": True,
        "ports": [
            {"port": port, "addresses": sorted(addresses)}
            for port, addresses in sorted(found.items())
        ],
    }


SEVERITIES = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "informational": 6,
    "debug": 7,
}


def syslog_line(
    message: str,
    *,
    severity: str = "informational",
    app: str = "omnishield",
    hostname: str = "omnishield",
    timestamp: str | None = None,
) -> str:
    if severity not in SEVERITIES:
        raise FederationError(f"unknown severity {severity!r}")
    if not message:
        raise FederationError("an empty syslog message is not useful")
    priority = 8 + SEVERITIES[severity]
    moment = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"<{priority}>1 {moment} {hostname} {app} - - {message}"


def send_syslog(target: tuple[str, int], line: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        return sender.sendto(line.encode("utf-8"), target)


def sntp_request() -> bytes:
    packet = bytearray(48)
    packet[0] = 0x1B
    return bytes(packet)


def parse_sntp(response: bytes) -> dict[str, Any]:
    if len(response) < 48:
        raise FederationError("an SNTP reply is 48 bytes")
    transmit = response[40:48]
    seconds = struct.unpack(">I", transmit[:4])[0]
    fraction = struct.unpack(">I", transmit[4:])[0] / 2**32
    if seconds == 0:
        raise FederationError("the server did not stamp the reply")
    unix = seconds - 2_208_988_800 + fraction
    return {
        "unix": round(unix, 3),
        "iso": datetime.fromtimestamp(unix, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def sntp_query(server: str, *, port: int = 123, timeout: float = 2.0) -> dict[str, Any]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(sntp_request(), (server, port))
        response, _ = client.recvfrom(48)
    parsed = parse_sntp(response)
    parsed["server"] = server
    parsed["offset_s"] = round(parsed["unix"] - time.time(), 3)
    return parsed


def inventory(*, arp: str = "/proc/net/arp", tcp: str = "/proc/net/tcp") -> dict[str, Any]:
    table = neighbours(arp)
    ports = listening_ports(tcp)
    return {
        "neighbours": table,
        "listening": ports,
        "neighbour_count": len(table["entries"]),
        "listening_count": len(ports["ports"]),
    }
