import socket
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from omnishield.p3_tunnel import (
    MAGIC,
    EphemeralChannel,
    FrameError,
    FrameReplay,
    HandshakeError,
    RekeyPolicy,
    _recv_msg,
    _send_msg,
    client_handshake,
    demo,
)

CLIENT_KEY = b"c" * 32
SERVER_KEY = b"s" * 32


def _pair(policy=None):
    client_ratchet = x25519.X25519PrivateKey.generate()
    server_ratchet = x25519.X25519PrivateKey.generate()
    return (
        EphemeralChannel(
            CLIENT_KEY,
            SERVER_KEY,
            send_dir=0,
            own_ratchet=client_ratchet,
            peer_ratchet=server_ratchet.public_key(),
            policy=policy,
        ),
        EphemeralChannel(
            SERVER_KEY,
            CLIENT_KEY,
            send_dir=1,
            own_ratchet=server_ratchet,
            peer_ratchet=client_ratchet.public_key(),
            policy=policy,
        ),
    )


def test_demo_runs_a_real_handshake():
    assert demo() == [
        "hello -> echo:hello",
        "post-quantum ready -> echo:post-quantum ready",
    ]


def test_rekey_after_packet_threshold():
    client, server = _pair(RekeyPolicy(packets=2, seconds=3600))
    initial = client.send_key_fingerprint
    server.open(client.seal(b"a"))
    server.open(client.seal(b"b"))
    assert client.send_key_fingerprint == initial
    frame = client.seal(b"c")
    assert client.send_key_fingerprint != initial
    assert server.open(frame) == b"c"


def test_receiver_ratchets_in_lockstep():
    client, server = _pair(RekeyPolicy(packets=1, seconds=3600))
    for index in range(6):
        assert server.open(client.seal(f"c{index}".encode())) == f"c{index}".encode()
        assert client.open(server.seal(f"s{index}".encode())) == f"s{index}".encode()


def test_captured_keys_cannot_open_the_next_frame():
    client, _server = _pair(RekeyPolicy(packets=1, seconds=3600))
    client.seal(b"warmup")
    frame = client.seal(b"after rekey")
    attacker = EphemeralChannel(
        SERVER_KEY,
        CLIENT_KEY,
        send_dir=1,
        own_ratchet=x25519.X25519PrivateKey.generate(),
        peer_ratchet=x25519.X25519PrivateKey.generate().public_key(),
    )
    with pytest.raises(FrameError):
        attacker.open(frame)


def test_tampered_frame_rejected():
    client, server = _pair()
    frame = bytearray(client.seal(b"hello"))
    frame[-1] ^= 0xFF
    with pytest.raises(FrameError):
        server.open(bytes(frame))


def test_replayed_frame_rejected():
    client, server = _pair()
    frame = client.seal(b"hello")
    assert server.open(frame) == b"hello"
    with pytest.raises(FrameReplay):
        server.open(frame)


def test_out_of_order_frame_rejected():
    client, server = _pair()
    first = client.seal(b"1")
    second = client.seal(b"2")
    assert server.open(second) == b"2"
    with pytest.raises(FrameReplay):
        server.open(first)


def test_padding_equalises_small_payloads():
    client, _ = _pair()
    other, _ = _pair()
    assert len(client.seal(b"a" * 10)) == len(other.seal(b"a" * 50))


def test_large_payload_roundtrip():
    client, server = _pair()
    payload = b"z" * 20_000
    assert server.open(client.seal(payload)) == payload


def test_handshake_rejects_modified_transcript():
    server_sock, client_sock = socket.socketpair()

    def fake_server():
        _recv_msg(server_sock)
        body = MAGIC + b"\x02" + b"\x01" * 32 + b"\x02" * 32
        _send_msg(server_sock, body + b"\x00" * 32)

    worker = threading.Thread(target=fake_server)
    worker.start()
    try:
        with pytest.raises(HandshakeError, match="transcript"):
            client_handshake(client_sock)
    finally:
        worker.join(timeout=5)
        server_sock.close()
        client_sock.close()
