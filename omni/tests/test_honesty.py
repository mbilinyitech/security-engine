import pytest

from omnishield.honesty import ClaimLedger, HonestyError, assess
from omnishield.hybrid import HybridSigner, HybridVerifier, SigError


def test_neutral_text_is_clean():
    report = assess("Tunakutana kesho saa tatu kwenye ofisi ya mradi.")
    assert report["verdict"] == "clean"
    assert report["flags"] == []


def test_phishing_style_text_is_flagged():
    report = assess(
        "Haraka! Thibitisha akaunti yako sasa hivi kwa kuweka PIN na password yako. "
        "Usimwambie mtu yeyote."
    )
    assert report["verdict"] == "deceptive"
    signals = {flag["signal"] for flag in report["flags"]}
    assert {"urgency", "credentials", "secrecy"} <= signals
    assert report["score"] >= 5


def test_a_claim_without_evidence_stays_unpublished(tmp_path):
    signer = HybridSigner.generate()
    ledger = ClaimLedger(tmp_path / "claims.jsonl", signer)
    document = ledger.record("Bei itapanda mara mbili.", source="chat")
    assert document["claim"]["status"] == "unverified"
    assert ledger.publish() == []
    assert len(ledger.unverified()) == 1


def test_attestation_makes_a_claim_publishable(tmp_path):
    signer = HybridSigner.generate()
    verifier = HybridVerifier(signer.public_identity)
    ledger = ClaimLedger(tmp_path / "claims.jsonl", signer)
    document = ledger.record("Bei itapanda mara mbili.", source="chat")
    ledger.attest(document, ["invoice-2026-11"], verifier=verifier)
    published = ledger.publish()
    assert len(published) == 1
    assert published[0]["evidence"] == ["invoice-2026-11"]
    assert ledger.unverified() == []


def test_attestation_needs_evidence(tmp_path):
    signer = HybridSigner.generate()
    verifier = HybridVerifier(signer.public_identity)
    ledger = ClaimLedger(tmp_path / "claims.jsonl", signer)
    document = ledger.record("Madai.", source="chat")
    with pytest.raises(HonestyError, match="evidence"):
        ledger.attest(document, [], verifier=verifier)


def test_a_tampered_claim_is_rejected(tmp_path):
    signer = HybridSigner.generate()
    verifier = HybridVerifier(signer.public_identity)
    ledger = ClaimLedger(tmp_path / "claims.jsonl", signer)
    document = ledger.record("Madai ya awali.", source="chat")
    document["claim"]["text"] = "Madai yaliyobadilishwa."
    with pytest.raises(SigError):
        ledger.verify_claim(document, verifier)


def test_a_claim_needs_a_source(tmp_path):
    ledger = ClaimLedger(tmp_path / "claims.jsonl", HybridSigner.generate())
    with pytest.raises(HonestyError, match="source"):
        ledger.record("Madai.", source="  ")
