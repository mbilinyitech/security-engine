import pytest

from omnishield.hybrid import ExpiredError, HybridVerifyError, ReplayError
from omnishield.keystore import FileKeyStore
from omnishield.p2_identity import (
    CounterStore,
    DeviceIdentity,
    is_hardware_rooted,
    sign_media,
    verify_media,
    verify_response,
)

CHALLENGE = bytes(range(32))


@pytest.fixture()
def device(tmp_path):
    return DeviceIdentity.create(
        FileKeyStore(tmp_path / "keys"), "phone", counters=CounterStore(tmp_path / "c.json")
    )


def test_challenge_response_roundtrip(device):
    document = device.respond(CHALLENGE, "login")
    payload = verify_response(
        document,
        device.identity,
        server_nonce=CHALLENGE,
        expected_context="login",
        counters=CounterStore(),
    )
    assert payload["counter"] == 1
    assert payload["key_origin"] == "file"


def test_replayed_response_rejected(device):
    document = device.respond(CHALLENGE, "login")
    counters = CounterStore()
    verify_response(document, device.identity, server_nonce=CHALLENGE, counters=counters)
    with pytest.raises(ReplayError):
        verify_response(document, device.identity, server_nonce=CHALLENGE, counters=counters)


def test_wrong_challenge_rejected(device):
    document = device.respond(CHALLENGE, "login")
    with pytest.raises(HybridVerifyError, match="challenge"):
        verify_response(document, device.identity, server_nonce=b"\x00" * 32)


def test_context_binding_enforced(device):
    document = device.respond(CHALLENGE, "login")
    with pytest.raises(HybridVerifyError, match="context"):
        verify_response(document, device.identity, server_nonce=CHALLENGE, expected_context="payment")


def test_other_device_key_rejected(device, tmp_path):
    other = DeviceIdentity.create(FileKeyStore(tmp_path / "other"), "other")
    document = device.respond(CHALLENGE, "login")
    with pytest.raises(HybridVerifyError):
        verify_response(document, other.identity, server_nonce=CHALLENGE)


def test_clock_skew_rejected(device):
    document = device.respond(CHALLENGE, "login", ttl_ms=600_000)
    device_time = document["payload"]["device_time_ms"]
    with pytest.raises(ExpiredError):
        verify_response(document, device.identity, server_nonce=CHALLENGE, now=device_time + 120_000)


def test_counter_persists_across_instances(tmp_path):
    path = tmp_path / "counters.json"
    CounterStore(path).record("dev", 5)
    assert CounterStore(path).current("dev") == 5


def test_counter_must_advance():
    store = CounterStore()
    store.record("dev", 5)
    with pytest.raises(ReplayError):
        store.record("dev", 5)
    with pytest.raises(ReplayError):
        store.record("dev", 4)


def test_identity_persists_in_keystore(tmp_path):
    keystore = FileKeyStore(tmp_path / "keys")
    device = DeviceIdentity.create(keystore, "phone")
    assert DeviceIdentity.load(keystore, "phone").device_id == device.device_id


def test_media_credential_roundtrip(device, tmp_path):
    media = tmp_path / "clip.mp4"
    media.write_bytes(b"\x00" * 2048)
    document = sign_media(media, device, capture_origin="camera-0")
    payload = verify_media(media, document, device.identity)
    assert payload["capture_origin"] == "camera-0"
    assert payload["size"] == 2048


def test_media_tamper_rejected(device, tmp_path):
    media = tmp_path / "clip.mp4"
    media.write_bytes(b"\x00" * 2048)
    document = sign_media(media, device)
    media.write_bytes(b"different bytes")
    with pytest.raises(HybridVerifyError):
        verify_media(media, document, device.identity)


def test_media_from_other_signer_rejected(device, tmp_path):
    media = tmp_path / "clip.mp4"
    media.write_bytes(b"\x00" * 64)
    document = sign_media(media, device)
    other = DeviceIdentity.create(FileKeyStore(tmp_path / "other"), "other")
    with pytest.raises(HybridVerifyError):
        verify_media(media, document, other.identity)


def test_hardware_root_detection():
    assert not is_hardware_rooted({"key_origin": "file"})
    assert is_hardware_rooted({"key_origin": "tpm2"})
