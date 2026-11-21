import pytest

from omnishield.hybrid import (
    MAX_TTL_MS,
    ExpiredError,
    HybridSigner,
    HybridVerifier,
    HybridVerifyError,
    PayloadMismatch,
    PolicyError,
    PublicIdentity,
    ReplayError,
    VersionLockError,
    now_ms,
)
from omnishield.replay import ReplayCache


@pytest.fixture()
def signer():
    return HybridSigner.generate()


def test_sign_and_verify_both_halves(signer):
    envelope = signer.sign(b"payload", domain="test")
    assert len(bytes.fromhex(envelope["sig_ed25519"])) == 64
    assert len(bytes.fromhex(envelope["sig_mldsa"])) == 2420
    HybridVerifier(signer.public_identity).verify(envelope, b"payload", expected_domain="test")


def test_payload_tamper_rejected(signer):
    envelope = signer.sign(b"payload", domain="test")
    with pytest.raises(PayloadMismatch):
        HybridVerifier(signer.public_identity).verify(envelope, b"payloaD")


def test_ml_dsa_half_is_mandatory(signer):
    envelope = signer.sign(b"payload", domain="test")
    attacker = HybridSigner.generate()
    forged = dict(envelope, sig_mldsa=attacker.sign(b"payload", domain="test")["sig_mldsa"])
    with pytest.raises(HybridVerifyError, match="ML-DSA"):
        HybridVerifier(signer.public_identity).verify(forged, b"payload")


def test_ed25519_half_is_mandatory(signer):
    envelope = signer.sign(b"payload", domain="test")
    forged = dict(envelope, sig_ed25519="00" * 64)
    with pytest.raises(HybridVerifyError, match="Ed25519"):
        HybridVerifier(signer.public_identity).verify(forged, b"payload")


def test_protocol_downgrade_blocked(signer):
    envelope = signer.sign(b"x", domain="tls", proto_id="tls", proto_version=13)
    with pytest.raises(VersionLockError, match="downgrade"):
        HybridVerifier(signer.public_identity).verify(envelope, b"x", expected_proto=("tls", 12))


def test_version_hash_tamper_blocked(signer):
    envelope = dict(signer.sign(b"x", domain="d"))
    envelope["proto_version"] = 0
    with pytest.raises(VersionLockError):
        HybridVerifier(signer.public_identity).verify(envelope, b"x")


def test_expired_envelope_rejected(signer):
    envelope = signer.sign(b"x", domain="d", ttl_ms=1_000, issued_at_ms=now_ms() - 10_000)
    with pytest.raises(ExpiredError, match="expired"):
        HybridVerifier(signer.public_identity).verify(envelope, b"x")


def test_future_envelope_rejected(signer):
    envelope = signer.sign(b"x", domain="d", ttl_ms=60_000, issued_at_ms=now_ms() + 600_000)
    with pytest.raises(ExpiredError, match="not valid yet"):
        HybridVerifier(signer.public_identity).verify(envelope, b"x")


def test_replay_rejected(signer):
    envelope = signer.sign(b"x", domain="d")
    verifier = HybridVerifier(signer.public_identity)
    cache = ReplayCache()
    verifier.verify(envelope, b"x", replay=cache)
    with pytest.raises(ReplayError):
        verifier.verify(envelope, b"x", replay=cache)


def test_wrong_key_rejected(signer):
    envelope = signer.sign(b"x", domain="d")
    other = HybridSigner.generate()
    with pytest.raises(HybridVerifyError, match="different key"):
        HybridVerifier(other.public_identity).verify(envelope, b"x")


def test_ttl_policy_enforced(signer):
    with pytest.raises(PolicyError):
        signer.sign(b"x", domain="d", ttl_ms=MAX_TTL_MS + 1)


def test_domain_binding_enforced(signer):
    envelope = signer.sign(b"x", domain="login")
    with pytest.raises(HybridVerifyError, match="domain"):
        HybridVerifier(signer.public_identity).verify(envelope, b"x", expected_domain="payment")


def test_signer_serialisation_roundtrip(signer):
    restored = HybridSigner.from_dict(signer.to_dict())
    assert restored.public_identity.key_id == signer.public_identity.key_id
    envelope = restored.sign(b"x", domain="d")
    HybridVerifier(signer.public_identity).verify(envelope, b"x")


def test_public_identity_rejects_mismatched_key_id(signer):
    document = signer.public_identity.to_dict()
    document["key_id"] = "00" * 16
    with pytest.raises(HybridVerifyError):
        PublicIdentity.from_dict(document)


def test_nonce_is_unique_per_signature(signer):
    first = signer.sign(b"x", domain="d")
    second = signer.sign(b"x", domain="d")
    assert first["nonce"] != second["nonce"]


def test_canonical_encoding_is_stable():
    from omnishield.canonical import canonical_bytes

    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
