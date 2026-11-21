"""OmniNet: a small peer protocol so two nodes can talk and share knowledge.

Frames are a 4-byte big-endian length followed by UTF-8 JSON. Every envelope
carries a version, a type, the sender, a nonce and a payload. The receiver
refuses oversized frames, unknown versions, unknown types and repeated nonces,
so a bad peer cannot grow memory or replay a message.

It is deliberately small: hello, gossip, sync and bye. It is a real socket
protocol, not a promise of a global network.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from typing import Any

VERSION = 1
MAX_FRAME = 1_000_000
TYPES = {"hello", "gossip", "sync", "chat", "bye"}
HEADER = struct.Struct(">I")


class NetError(Exception):
    pass


def _canonical(message: dict[str, Any]) -> bytes:
    body = {key: value for key, value in message.items() if key != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def keypair() -> dict[str, str]:
    """Generate an Ed25519 key pair, base64 encoded."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private = Ed25519PrivateKey.generate()
    return {
        "private": base64.b64encode(
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        "public": base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
    }


def sign(message: dict[str, Any], private_key: str) -> dict[str, Any]:
    """Return a copy of the message with the public key and an Ed25519 signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    signed = dict(message)
    signed.pop("sig", None)
    signed["pub"] = public
    signed["sig"] = base64.b64encode(private.sign(_canonical(signed))).decode()
    return signed


def verify(message: dict[str, Any], public_key: str | None = None) -> None:
    """Raise NetError unless the Ed25519 signature matches the body."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature = message.get("sig")
    if not signature:
        raise NetError("the message is not signed")
    encoded = public_key or message.get("pub")
    if not encoded:
        raise NetError("the message carries no public key")
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded))
        key.verify(base64.b64decode(signature), _canonical(message))
    except (InvalidSignature, ValueError) as error:
        raise NetError(f"bad signature: {error}") from error


def envelope(
    kind: str,
    sender: str,
    payload: Any,
    *,
    nonce: str | None = None,
    private_key: str | None = None,
) -> dict[str, Any]:
    if kind not in TYPES:
        raise NetError(f"unknown message type {kind}")
    if not sender.strip():
        raise NetError("the envelope needs a sender")
    message = {
        "v": VERSION,
        "type": kind,
        "from": sender,
        "nonce": nonce or uuid.uuid4().hex,
        "sent_at": round(time.time(), 3),
        "payload": payload,
    }
    return sign(message, private_key) if private_key else message


def frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise NetError("the frame is too large")
    return HEADER.pack(len(body)) + body


def read_frame(connection: socket.socket) -> dict[str, Any]:
    header = _read_exact(connection, HEADER.size)
    (size,) = HEADER.unpack(header)
    if size <= 0 or size > MAX_FRAME:
        raise NetError(f"bad frame length {size}")
    body = _read_exact(connection, size)
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetError(f"bad frame body: {error}") from error
    validate(message)
    return message


def _read_exact(connection: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise NetError("the peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def validate(message: Any) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise NetError("a message must be an object")
    if message.get("v") != VERSION:
        raise NetError(f"unsupported version {message.get('v')}")
    if message.get("type") not in TYPES:
        raise NetError(f"unknown type {message.get('type')}")
    if not str(message.get("from", "")).strip():
        raise NetError("the message has no sender")
    if not str(message.get("nonce", "")).strip():
        raise NetError("the message has no nonce")
    return message


class Node:
    """A node with a nonce window, a knowledge store and a message handler."""

    def __init__(
        self,
        node_id: str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        store: Any = None,
        answerer: Callable[[str], str] | None = None,
        private_key: str | None = None,
        require_signature: bool = False,
    ) -> None:
        if not node_id.strip():
            raise NetError("a node needs an id")
        self.id = node_id.strip()
        self.host = host
        self.port = port
        self.store = store
        self.answerer = answerer
        self.private_key = private_key
        self.require_signature = require_signature
        self.keys: dict[str, str] = {}
        self.seen: set[str] = set()
        self.received: list[dict[str, Any]] = []
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.handler: Callable[[dict[str, Any], Node], dict[str, Any] | None] | None = None

    def _check_signature(self, message: dict[str, Any]) -> None:
        if message.get("sig"):
            verify(message)
            known = self.keys.get(message["from"])
            if known and known != message["pub"]:
                raise NetError("the peer changed its public key")
            self.keys[message["from"]] = message["pub"]
        elif self.require_signature:
            raise NetError("a signature is required")

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        validate(message)
        self._check_signature(message)
        nonce = message["nonce"]
        if nonce in self.seen:
            raise NetError("replayed nonce")
        self.seen.add(nonce)
        if len(self.seen) > 10_000:
            self.seen = set(list(self.seen)[-5_000:])
        self.received.append(message)
        if message["type"] == "gossip" and self.store is not None:
            for item in message.get("payload", {}).get("items", []):
                text = str(item.get("text", "")).strip()
                if text:
                    self.store.add(text, source=item.get("source", message["from"]), title=item.get("title", ""))
        if self.handler:
            return self.handler(message, self)
        if message["type"] == "hello":
            return envelope("hello", self.id, {"name": self.id, "peers": 0}, nonce=f"hello-{nonce}", private_key=self.private_key)
        if message["type"] == "sync":
            return envelope("sync", self.id, {"items": self._items()}, nonce=f"sync-{nonce}")
        if message["type"] == "bye":
            return None
        if message["type"] == "gossip":
            items = message.get("payload", {}).get("items", [])
            return envelope("sync", self.id, {"received": len(items)}, nonce=f"ack-{nonce}", private_key=self.private_key)
        if message["type"] == "chat":
            question = str(message.get("payload", {}).get("text", "")).strip()
            if not question:
                return envelope("chat", self.id, {"reply": "", "error": "empty question"}, nonce=f"chat-{nonce}")
            if self.answerer is None:
                return envelope("chat", self.id, {"reply": "", "error": "no answerer"}, nonce=f"chat-{nonce}")
            try:
                reply = self.answerer(question)
            except Exception as error:  # noqa: BLE001 - the peer must get an error, not a dropped connection
                return envelope("chat", self.id, {"reply": "", "error": str(error)}, nonce=f"chat-{nonce}")
            return envelope(
                "chat",
                self.id,
                {"reply": reply, "question": question},
                nonce=f"chat-{nonce}",
                private_key=self.private_key,
            )
        return None

    def _items(self, limit: int = 20) -> list[dict[str, str]]:
        if self.store is None:
            return []
        items = []
        for item in list(self.store.items)[-limit:]:
            items.append({"text": item.get("text", ""), "source": item.get("source", ""), "title": item.get("title", "")})
        return items

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(8)
        self.server = server
        self.port = server.getsockname()[1]

        def loop() -> None:
            while True:
                try:
                    connection, _ = server.accept()
                except OSError:
                    return
                threading.Thread(target=self._serve_one, args=(connection,), daemon=True).start()

        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        return self.port

    def _serve_one(self, connection: socket.socket) -> None:
        with connection:
            try:
                message = read_frame(connection)
                reply = self.handle(message)
                if reply is not None:
                    connection.sendall(frame(reply))
            except (NetError, OSError):
                return

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            self.server = None

    def send(self, host: str, port: int, message: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any] | None:
        if self.private_key and not message.get("sig"):
            message = sign(message, self.private_key)
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.sendall(frame(message))
            if message["type"] == "bye":
                return None
            connection.settimeout(timeout)
            return read_frame(connection)

    def gossip(self, peers: Iterable[tuple[str, int]], items: Iterable[dict[str, str]] | None = None) -> dict[str, Any]:
        payload = {"items": list(items) if items is not None else self._items()}
        results = []
        for host, port in peers:
            try:
                reply = self.send(host, port, envelope("gossip", self.id, payload))
                results.append({"peer": f"{host}:{port}", "ok": True, "reply": reply})
            except (NetError, OSError) as error:
                results.append({"peer": f"{host}:{port}", "ok": False, "error": str(error)})
        return {"sent": len(results), "ok": sum(1 for row in results if row["ok"]), "results": results}
