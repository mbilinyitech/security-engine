import hashlib

import pytest

from omnishield.audit import AuditLog
from omnishield.export import export_all
from omnishield.hybrid import HybridSigner
from omnishield.memory_store import PersistentMemory
from omnishield.payments import PaymentService


class _Gateway:
    def charge(self, intent):
        return "rcpt-test"


@pytest.fixture
def state(tmp_path):
    audit = AuditLog(tmp_path / "audit.log", key=b"k" * 32)
    memory = PersistentMemory(tmp_path / "memory.db")
    memory.insert("mkutano wa bodi", "1,0,0", salience=0.8)
    memory.insert("barua ya benki", "0,1,0", salience=0.5)
    audit.append("test.memory", {"inserted": 2})

    requester = HybridSigner.generate()
    approver = HybridSigner.generate()
    payments = PaymentService(tmp_path / "payments.jsonl", requester, gateway=_Gateway())
    intent = payments.create(1_500, "TZS", "Amina")
    approval = payments.approve(intent, approver, approver_name="human:test")
    payments.settle(intent, approval, approver.public_identity)
    audit.append("test.payment", {"settled": 1})
    return tmp_path, audit.path


def test_export_writes_tidy_csv_for_every_source(state, tmp_path):
    root, audit_path = state
    out = tmp_path / "data"
    manifest = export_all(
        out,
        memory_db=root / "memory.db",
        payments_ledger=root / "payments.jsonl",
        audit_log=audit_path,
    )
    assert manifest["product"] == "OmniShield"
    rows = {name: info["rows"] for name, info in manifest["files"].items()}
    assert set(rows) == {
        "features.csv",
        "components.csv",
        "doctor.csv",
        "audit.csv",
        "memory.csv",
        "payments.csv",
        "stealth.csv",
        "prediction.csv",
        "layers.csv",
        "image_quality.csv",
    }
    assert rows["features.csv"] == 500
    assert rows["components.csv"] >= 10
    assert rows["doctor.csv"] >= 10
    assert rows["memory.csv"] == 2
    assert rows["payments.csv"] == 1
    assert rows["audit.csv"] == 2


def test_manifest_digests_match_the_files(state, tmp_path):
    root, audit_path = state
    out = tmp_path / "data"
    manifest = export_all(out, memory_db=root / "memory.db", audit_log=audit_path)
    for name, info in manifest["files"].items():
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        assert digest == info["sha256"]
    manifest_csv = (out / "manifest.csv").read_text(encoding="utf-8")
    assert manifest_csv.splitlines()[0] == "file,rows,sha256"
    assert len(manifest_csv.splitlines()) == len(manifest["files"]) + 1


def test_export_refuses_a_missing_source(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_all(tmp_path / "data", memory_db=tmp_path / "missing.db")
