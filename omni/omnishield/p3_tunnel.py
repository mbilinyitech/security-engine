"""Protocol 3: ephemeral, ratcheting tunnel.

X25519 handshake, HKDF-derived directional keys, ChaCha20-Poly1305 per frame, and
a Diffie-Hellman ratchet that replaces keys after N packets or T seconds. Each
rekey carries a fresh ephemeral public key, so capturing a frame does not give
an attacker the material for the next one: the new key needs a private key that
never leaves the endpoint. Payloads are padded into fixed buckets and every
frame counter is monotonic, so neither size nor replay leaks.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Self

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .hybrid import HybridVerifier, PublicIdentity

MAGIC = b"OHS3"
VERSION = 1
FLAG_REKEY = 0x01
HS_DOMAIN = "omnishield.p3.handshake"
HS_PROTO = ("tunnel-handshake", 1)
MAX_IDENTITY = 8192
HEADER = struct.Struct(">4sBBQ")
LENGTH = struct.Struct(">I")
PAD_BUCKETS = (64, 256, 1024, 4096, 16384)
MAX_FRAME = 1 << 20


class TunnelError(Exception):
    pass


class HandshakeError(TunnelError):
    pass


class FrameError(TunnelError):
    pass


class FrameReplay(TunnelError):
    pass


@dataclass(frozen=True)
class RekeyPolicy:
    packets: int = 100
    seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.packets <= 0 or self.seconds <= 0:
            raise ValueError("rekey thresholds must be positive")


def _hkdf(material: bytes, info: bytes, *, salt: bytes | None = None, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(material)


def _ratcheted_key(shared: bytes, old_key: bytes) -> bytes:
    return _hkdf(shared + old_key, b"omnishield/p3/dh-rekey")


def _pad(plaintext: bytes) -> bytes:
    needed = 4 + len(plaintext)
    target = next((bucket for bucket in PAD_BUCKETS if needed <= bucket), needed)
    return struct.pack(">I", len(plaintext)) + plaintext + b"\x00" * (target - needed)


def _unpad(blob: bytes) -> bytes:
    if len(blob) < 4:
        raise FrameError("padded payload is truncated")
    (size,) = LENGTH.unpack_from(blob, 0)
    if size > len(blob) - 4:
        raise FrameError("padded payload declares an impossible length")
    return blob[4 : 4 + size]


class EphemeralChannel:
    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        *,
        send_dir: int,
        own_ratchet: x25519.X25519PrivateKey,
        peer_ratchet: x25519.X25519PublicKey,
        policy: RekeyPolicy | None = None,
        peer_identity_key_id: str | None = None,
    ):
        if len(send_key) != 32 or len(recv_key) != 32:
            raise ValueError("channel keys must be 32 bytes")
        self._send_key = send_key
        self._recv_key = recv_key
        self._send_dir = send_dir
        self._own_ratchet = own_ratchet
        self._peer_ratchet = peer_ratchet
        self._policy = policy or RekeyPolicy()
        self._counter = 0
        self._last_recv = 0
        self._sent_since_rekey = 0
        self._send_window_start = time.monotonic()
        self.rekeys = 0
        self.peer_identity_key_id = peer_identity_key_id

    @property
    def send_key_fingerprint(self) -> str:
        return hashlib.sha256(self._send_key).hexdigest()[:16]

    def _should_rekey(self) -> bool:
        if not self._sent_since_rekey:
            return False
        if self._sent_since_rekey >= self._policy.packets:
            return True
        return (time.monotonic() - self._send_window_start) >= self._policy.seconds

    def _seal_header(self, flags: int, counter: int, public: bytes) -> bytes:
        return HEADER.pack(MAGIC, VERSION, flags, counter) + bytes([len(public)]) + public

    def seal(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        flags = 0
        public = b""
        if self._should_rekey():
            self._own_ratchet = x25519.X25519PrivateKey.generate()
            shared = self._own_ratchet.exchange(self._peer_ratchet)
            self._send_key = _ratcheted_key(shared, self._send_key)
            public = self._own_ratchet.public_key().public_bytes_raw()
            flags = FLAG_REKEY
            self._sent_since_rekey = 0
            self._send_window_start = time.monotonic()
            self.rekeys += 1
        self._counter += 1
        header = self._seal_header(flags, self._counter, public)
        nonce = self._counter.to_bytes(8, "big") + bytes([self._send_dir]) + b"\x00" * 3
        ciphertext = ChaCha20Poly1305(self._send_key).encrypt(nonce, _pad(bytes(plaintext)), header)
        self._sent_since_rekey += 1
        return header + LENGTH.pack(len(ciphertext)) + ciphertext

    def open(self, frame: bytes) -> bytes:
        if len(frame) < HEADER.size + 1:
            raise FrameError("frame is shorter than its header")
        magic, version, flags, counter = HEADER.unpack_from(frame, 0)
        if magic != MAGIC:
            raise FrameError("bad frame magic")
        if version != VERSION:
            raise FrameError(f"unsupported frame version {version}")
        public_length = frame[HEADER.size]
        body_start = HEADER.size + 1 + public_length
        if public_length not in (0, 32) or len(frame) < body_start + LENGTH.size:
            raise FrameError("malformed ratchet field")
        public = frame[HEADER.size + 1 : body_start]
        header = frame[:body_start]
        (declared,) = LENGTH.unpack_from(frame, body_start)
        ciphertext = frame[body_start + LENGTH.size :]
        if declared != len(ciphertext) or declared > MAX_FRAME:
            raise FrameError("frame length mismatch")
        if counter <= self._last_recv:
            raise FrameReplay(f"frame counter {counter} is not greater than {self._last_recv}")
        if flags & FLAG_REKEY:
            if public_length != 32:
                raise FrameError("rekey frame is missing its ephemeral key")
            try:
                peer = x25519.X25519PublicKey.from_public_bytes(public)
                shared = self._own_ratchet.exchange(peer)
            except Exception as exc:
                raise FrameError("invalid ratchet key in rekey frame") from exc
            self._recv_key = _ratcheted_key(shared, self._recv_key)
            self._peer_ratchet = peer
            self.rekeys += 1
        nonce = counter.to_bytes(8, "big") + bytes([1 - self._send_dir]) + b"\x00" * 3
        try:
            padded = ChaCha20Poly1305(self._recv_key).decrypt(nonce, ciphertext, header)
        except Exception as exc:
            raise FrameError("frame authentication failed") from exc
        self._last_recv = counter
        return _unpad(padded)


def _send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(LENGTH.pack(len(data)) + data)


def _recv_msg(sock: socket.socket) -> bytes:
    (size,) = LENGTH.unpack(_recv_exact(sock, LENGTH.size))
    if size > MAX_FRAME:
        raise HandshakeError("handshake message is too large")
    return _recv_exact(sock, size)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise HandshakeError("peer closed the connection mid-handshake")
        chunks.extend(chunk)
    return bytes(chunks)


def _derive(shared: bytes, transcript_digest: bytes) -> tuple[bytes, bytes]:
    keys = _hkdf(shared, b"omnishield/p3/keys", salt=transcript_digest, length=64)
    return keys[:32], keys[32:]


def client_handshake(
    sock: socket.socket,
    *,
    policy: RekeyPolicy | None = None,
    expected_identity: PublicIdentity | None = None,
) -> EphemeralChannel:
    private = x25519.X25519PrivateKey.generate()
    client_nonce = secrets.token_bytes(32)
    hs1 = MAGIC + b"\x01" + private.public_key().public_bytes_raw() + client_nonce
    _send_msg(sock, hs1)
    hs2 = _recv_msg(sock)
    if len(hs2) < 5 + 32 + 32 + 32 or hs2[:5] != MAGIC + b"\x02":
        raise HandshakeError("malformed server handshake")
    body, presented, tail = hs2[:69], hs2[69:101], hs2[101:]
    digest = hashlib.sha256(hs1 + body).digest()
    if not hmac.compare_digest(digest, presented):
        raise HandshakeError("handshake transcript was modified in flight")
    peer_identity_key_id = None
    if tail:
        if len(tail) < LENGTH.size:
            raise HandshakeError("truncated identity block in handshake")
        (size,) = LENGTH.unpack_from(tail, 0)
        if size > MAX_IDENTITY or len(tail) < LENGTH.size + size:
            raise HandshakeError("malformed identity block in handshake")
        if expected_identity is None:
            raise HandshakeError("server presented an identity but none was expected")
        document = json.loads(tail[LENGTH.size : LENGTH.size + size].decode("utf-8"))
        HybridVerifier(expected_identity).verify(
            document, digest, expected_domain=HS_DOMAIN, expected_proto=HS_PROTO
        )
        peer_identity_key_id = expected_identity.key_id.hex()
    elif expected_identity is not None:
        raise HandshakeError("server identity is required but was not presented")
    try:
        peer = x25519.X25519PublicKey.from_public_bytes(body[5:37])
        shared = private.exchange(peer)
    except Exception as exc:
        raise HandshakeError("invalid server key share") from exc
    send_key, recv_key = _derive(shared, digest)
    return EphemeralChannel(
        send_key,
        recv_key,
        send_dir=0,
        own_ratchet=private,
        peer_ratchet=peer,
        policy=policy,
        peer_identity_key_id=peer_identity_key_id,
    )


def server_handshake(
    sock: socket.socket,
    *,
    policy: RekeyPolicy | None = None,
    identity: Any = None,
) -> EphemeralChannel:
    """Complete the handshake. Pass a DeviceIdentity to authenticate the server.

    The identity envelope signs the handshake transcript digest, so a
    man-in-the-middle cannot present a valid signature for a modified exchange.
    """
    hs1 = _recv_msg(sock)
    if len(hs1) != 5 + 32 + 32 or hs1[:5] != MAGIC + b"\x01":
        raise HandshakeError("malformed client handshake")
    client_pub = hs1[5:37]
    private = x25519.X25519PrivateKey.generate()
    body = MAGIC + b"\x02" + private.public_key().public_bytes_raw() + secrets.token_bytes(32)
    digest = hashlib.sha256(hs1 + body).digest()
    message = body + digest
    if identity is not None:
        envelope = identity.signer.sign(
            digest,
            domain=HS_DOMAIN,
            proto_id=HS_PROTO[0],
            proto_version=HS_PROTO[1],
            ttl_ms=60_000,
        )
        blob = json.dumps(envelope, sort_keys=True).encode("utf-8")
        if len(blob) > MAX_IDENTITY:
            raise HandshakeError("identity block is too large")
        message += LENGTH.pack(len(blob)) + blob
    _send_msg(sock, message)
    try:
        peer = x25519.X25519PublicKey.from_public_bytes(client_pub)
        shared = private.exchange(peer)
    except Exception as exc:
        raise HandshakeError("invalid client key share") from exc
    client_to_server, server_to_client = _derive(shared, digest)
    return EphemeralChannel(
        server_to_client, client_to_server, send_dir=1, own_ratchet=private, peer_ratchet=peer, policy=policy
    )


class Tunnel:
    """Message-oriented encrypted channel over an existing socket."""

    def __init__(self, sock: socket.socket, channel: EphemeralChannel):
        self.sock = sock
        self.channel = channel

    def send(self, data: bytes) -> None:
        _send_msg(self.sock, self.channel.seal(data))

    def recv(self) -> bytes:
        return self.channel.open(_recv_msg(self.sock))

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def demo(
    messages: tuple[bytes, ...] = (b"hello", b"post-quantum ready"),
    *,
    policy: RekeyPolicy | None = None,
    identity: Any = None,
) -> list[str]:
    """Run a real handshake over a socket pair and echo the messages back.

    Pass a DeviceIdentity to authenticate the server side of the handshake.
    """
    server_sock, client_sock = socket.socketpair()
    received: list[str] = []

    def serve() -> None:
        channel = server_handshake(server_sock, policy=policy, identity=identity)
        with Tunnel(server_sock, channel) as tunnel:
            while True:
                try:
                    message = tunnel.recv()
                except (HandshakeError, OSError):
                    break
                tunnel.send(b"echo:" + message)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    expected = identity.identity if identity is not None else None
    with Tunnel(client_sock, client_handshake(client_sock, policy=policy, expected_identity=expected)) as tunnel:
        for message in messages:
            tunnel.send(message)
            received.append(f"{message.decode()} -> {tunnel.recv().decode()}")
    worker.join(timeout=5)
    return received
