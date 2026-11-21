import socket
import threading

import pytest

from omnishield.keystore import FileKeyStore
from omnishield.p2_identity import DeviceIdentity
from omnishield.p3_tunnel import (
    HandshakeError,
    RekeyPolicy,
    Tunnel,
    client_handshake,
    server_handshake,
)

POLICY = RekeyPolicy(packets=7, seconds=3600)


def _echo(sock, identity=None):
    channel = server_handshake(sock, identity=identity, policy=POLICY)
    with Tunnel(sock, channel) as tunnel:
        while True:
            try:
                message = tunnel.recv()
            except (HandshakeError, OSError):
                break
            tunnel.send(message)


def _roundtrip(family, host, identity=None):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        with conn:
            _echo(conn, identity)
        listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client = socket.create_connection((host, port), timeout=10)
    expected_identity = identity.identity if identity is not None else None
    with Tunnel(client, client_handshake(client, policy=POLICY, expected_identity=expected_identity)) as tunnel:
        for index in range(200):
            payload = f"ujumbe-{index}".encode()
            tunnel.send(payload)
            assert tunnel.recv() == payload
    worker.join(timeout=10)
    assert not worker.is_alive()


def test_tcp_ipv4_loopback_with_rekeying():
    _roundtrip(socket.AF_INET, "127.0.0.1")


def test_tcp_ipv6_loopback_with_rekeying():
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        probe.bind(("::1", 0))
        probe.close()
    except OSError:
        pytest.skip("IPv6 loopback is not available on this host")
    _roundtrip(socket.AF_INET6, "::1")


def test_tcp_with_authenticated_server(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "server")
    _roundtrip(socket.AF_INET, "127.0.0.1", identity=device)
