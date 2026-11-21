import json
import os

import pytest

from omnishield.audit import GENESIS, AuditError, AuditLog


def test_append_chains_entries(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    first = log.append("energy.tick", {"level": 10.0})
    second = log.append("memory.insert", {"id": 1})
    assert first != second
    assert log.verify() == 2
    entries = list(log.entries())
    assert entries[0].prev == GENESIS
    assert entries[1].prev == entries[0].hash
    assert entries[1].hash == log.head()


def test_verification_survives_a_reload(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    reloaded = AuditLog(path)
    assert reloaded.verify() == 2
    assert reloaded.head() == log.head()


def test_editing_an_entry_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append("a", {"amount": 1})
    log.append("b", {"amount": 2})

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["payload"]["amount"] = 999
    lines[0] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditError):
        AuditLog(path)


def test_removing_an_entry_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append("a", {})
    log.append("b", {})
    log.append("c", {})

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    with pytest.raises(AuditError):
        AuditLog(path)


def test_hmac_key_rejects_a_forged_chain(tmp_path):
    path = tmp_path / "audit.log"
    key = b"k" * 32
    log = AuditLog(path, key=key)
    log.append("a", {"x": 1})

    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["x"] = 2
    path.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(AuditError):
        AuditLog(path, key=key)


def test_keyed_log_cannot_be_verified_without_the_key(tmp_path):
    path = tmp_path / "audit.log"
    AuditLog(path, key=b"k" * 32).append("a", {})
    with pytest.raises(AuditError):
        AuditLog(path)


def test_audit_file_is_private(tmp_path):
    path = tmp_path / "audit.log"
    AuditLog(path).append("a", {})
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_append_rejects_bad_arguments(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    with pytest.raises(AuditError):
        log.append("", {})
    with pytest.raises(AuditError):
        log.append("a" * 65, {})
    with pytest.raises(AuditError):
        log.append("ok", ["not", "a", "mapping"])
