import stat
import threading
import unicodedata

import pytest

from omnishield.canonical import canonical_bytes
from omnishield.hybrid import HybridSigner, HybridVerifier, SigError
from omnishield.keystore import FileKeyStore
from omnishield.p2_identity import (
    CounterStore,
    DeviceIdentity,
    IdentityError,
    PinStore,
    verify_response,
)
from omnishield.p3_tunnel import (
    HandshakeError,
    Tunnel,
    client_handshake,
    server_handshake,
)
from omnishield.p4_allowlist import (
    MANIFEST_DOMAIN,
    MANIFEST_PROTO,
    AllowList,
    NotAllowed,
    build_manifest,
    verify_manifest,
)
from omnishield.replay import ReplayCache


@pytest.fixture()
def signer():
    return HybridSigner.generate()


@pytest.fixture()
def workspace(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 41 + 1\n")
    return root


@pytest.fixture()
def manifest(workspace, signer):
    return build_manifest([workspace / "app.py"], signer, base_dir=workspace)


class _SwappingAllowList(AllowList):
    """Swaps the artifact between lookup and read to prove load re-hashes."""

    def lookup(self, path):
        entry = super().lookup(path)
        (self.root / "app.py").write_text("SWAPPED = True\n")
        return entry


def test_load_module_hashes_the_bytes_it_executes(manifest, signer):
    allow = _SwappingAllowList(manifest, HybridVerifier(signer.public_identity))
    with pytest.raises(NotAllowed, match="changed between"):
        allow.load_module("app.py")


def test_symlink_artifact_rejected(workspace, signer, tmp_path):
    document = build_manifest([workspace / "app.py"], signer, base_dir=workspace)
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n")
    (workspace / "app.py").unlink()
    (workspace / "app.py").symlink_to(outside)
    with pytest.raises(NotAllowed, match="symlink"):
        verify_manifest(document, HybridVerifier(signer.public_identity))


def test_manifest_entry_cannot_escape_base_dir(workspace, signer, tmp_path):
    (tmp_path / "outside.txt").write_text("x")
    document = build_manifest([workspace / "app.py"], signer, base_dir=workspace)
    document["payload"]["entries"][0]["path"] = "../outside.txt"
    document["envelope"] = signer.sign(
        canonical_bytes(document["payload"]),
        domain=MANIFEST_DOMAIN,
        proto_id=MANIFEST_PROTO[0],
        proto_version=MANIFEST_PROTO[1],
    )
    with pytest.raises(NotAllowed, match="escapes"):
        verify_manifest(document, HybridVerifier(signer.public_identity))


def test_manifest_lookup_is_unicode_normalised(workspace, signer):
    name = unicodedata.normalize("NFC", "café.py")
    (workspace / name).write_text("VALUE = 1\n")
    document = build_manifest([workspace / name], signer, base_dir=workspace)
    allow = AllowList(document, HybridVerifier(signer.public_identity))
    decomposed = unicodedata.normalize("NFD", "café.py")
    assert allow.lookup(decomposed).path == name


def test_replay_cache_file_is_private(tmp_path):
    path = tmp_path / "state" / "replay.json"
    ReplayCache(path).check_and_record(b"k", b"n", 10**15, 1_000)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_counter_file_is_private(tmp_path):
    path = tmp_path / "state" / "counters.json"
    CounterStore(path).record("dev", 1)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_pin_store_blocks_key_change(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "phone")
    pins = PinStore(tmp_path / "pins.json")
    challenge = b"\x07" * 32
    verify_response(
        device.respond(challenge, "login"),
        device.identity,
        server_nonce=challenge,
        pins=pins,
        pin_name="amina@example.tz",
    )
    impostor = DeviceIdentity.create(FileKeyStore(tmp_path / "other"), "impostor")
    with pytest.raises(IdentityError, match="changed"):
        verify_response(
            impostor.respond(challenge, "login"),
            impostor.identity,
            server_nonce=challenge,
            pins=pins,
            pin_name="amina@example.tz",
        )


def test_pin_store_requires_a_name(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "phone")
    challenge = b"\x08" * 32
    with pytest.raises(IdentityError, match="pin_name"):
        verify_response(
            device.respond(challenge, "login"),
            device.identity,
            server_nonce=challenge,
            pins=PinStore(),
        )


def _serve(sock, identity=None, payload=b"ok"):
    channel = server_handshake(sock, identity=identity)
    with Tunnel(sock, channel) as tunnel:
        tunnel.send(payload)


def test_signed_handshake_binds_server_identity(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "server")
    server_sock, client_sock = socketpair()
    worker = threading.Thread(target=_serve, args=(server_sock, device))
    worker.start()
    channel = client_handshake(client_sock, expected_identity=device.identity)
    assert channel.peer_identity_key_id == device.device_id
    assert Tunnel(client_sock, channel).recv() == b"ok"
    worker.join(timeout=5)
    assert not worker.is_alive()


def test_unsigned_handshake_rejected_when_identity_required(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "server")
    server_sock, client_sock = socketpair()
    worker = threading.Thread(target=_serve, args=(server_sock,))
    worker.start()
    try:
        with pytest.raises(HandshakeError, match="required"):
            client_handshake(client_sock, expected_identity=device.identity)
    finally:
        worker.join(timeout=5)
        server_sock.close()
        client_sock.close()


def test_wrong_server_identity_rejected(tmp_path):
    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "server")
    other = DeviceIdentity.create(FileKeyStore(tmp_path / "other"), "other")
    server_sock, client_sock = socketpair()
    worker = threading.Thread(target=_serve, args=(server_sock, device))
    worker.start()
    try:
        with pytest.raises(SigError):
            client_handshake(client_sock, expected_identity=other.identity)
    finally:
        worker.join(timeout=5)
        server_sock.close()
        client_sock.close()


def socketpair():
    import socket

    return socket.socketpair()
