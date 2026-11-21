import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from omnishield.memory_store import MemoryStoreError, PersistentMemory, parse_vector

REPO = Path(__file__).resolve().parents[1]


def cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "omnishield.cli", *arguments],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )


def test_insert_survives_a_new_instance(tmp_path):
    db = tmp_path / "memory.db"
    first = PersistentMemory(db)
    identifier = first.insert("mkutano wa bodi", "1,0,0", salience=0.9)
    assert identifier == 1

    second = PersistentMemory(db)
    found = second.search("1,0,0", limit=1)
    assert found[0]["id"] == identifier
    assert second.insert("barua", "0,1,0") == 2, "ids continue after reload"


def test_state_persists_across_processes(tmp_path):
    db = tmp_path / "memory.db"
    inserted = cli("memory", "insert", "--db", str(db), "--content", "mkutano", "--embedding", "1,0")
    assert inserted.returncode == 0, inserted.stderr
    identifier = json.loads(inserted.stdout)["id"]

    searched = cli("memory", "search", "--db", str(db), "--embedding", "1,0", "--limit", "1")
    assert searched.returncode == 0, searched.stderr
    assert json.loads(searched.stdout)[0]["id"] == identifier

    verified = cli("memory", "verify", "--db", str(db))
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["ok"] is True


def test_verify_detects_a_hand_edited_database(tmp_path):
    db = tmp_path / "memory.db"
    store = PersistentMemory(db)
    store.insert("mkutano", "1,0")
    document = json.loads(db.read_text(encoding="utf-8"))
    document["items"][0]["content"] = "kitu kingine"
    db.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(MemoryStoreError, match="does not match"):
        PersistentMemory(db).verify()


def test_verify_detects_a_broken_audit_chain(tmp_path):
    db = tmp_path / "memory.db"
    store = PersistentMemory(db)
    store.insert("mkutano", "1,0")
    audit = db.with_name(db.name + ".audit.log")
    lines = audit.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["snapshot"] = "0" * 64
    lines[0] = json.dumps(entry, sort_keys=True)
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(MemoryStoreError, match="audit"):
        PersistentMemory(db)


def test_forget_leaves_a_tombstone(tmp_path):
    db = tmp_path / "memory.db"
    store = PersistentMemory(db)
    identifier = store.insert("kumbukumbu", "1,0")
    store.forget(identifier)
    stats = store.stats()
    assert stats["live"] == 0
    assert stats["tombstoned"] == 1


def test_database_is_private(tmp_path):
    db = tmp_path / "memory.db"
    PersistentMemory(db).insert("siri", "1,0")
    if os.name == "posix":
        assert db.stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "memory.db.audit.log").stat().st_mode & 0o777 == 0o600


def test_database_without_an_audit_trail_is_refused(tmp_path):
    db = tmp_path / "memory.db"
    document = {
        "version": 1,
        "capacity": 8,
        "decay_per_hour": 0.02,
        "floor": 0.05,
        "items": [
            {
                "id": 1,
                "content": "imewekwa kwa mkono",
                "embedding": [1.0],
                "created_ms": 0,
                "last_access_ms": 0,
                "access_count": 0,
                "salience": 0.5,
                "emotion": 0.0,
                "suppressed": False,
                "tombstone": False,
            }
        ],
    }
    db.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(MemoryStoreError, match="without an audit trail"):
        PersistentMemory(db).verify()


def test_bad_embeddings_are_rejected(tmp_path):
    store = PersistentMemory(tmp_path / "memory.db")
    with pytest.raises(MemoryStoreError):
        store.insert("x", "")
    with pytest.raises(MemoryStoreError):
        parse_vector("1,nan")
    with pytest.raises(MemoryStoreError):
        parse_vector("1,inf")
    assert parse_vector("[1, 0, 0]") == [1.0, 0.0, 0.0]
