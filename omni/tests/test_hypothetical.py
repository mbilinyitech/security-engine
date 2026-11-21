import pytest

from omnishield.hypothetical import HypotheticalError, HypotheticalMemory


def test_imagined_content_is_never_recalled_as_fact(tmp_path):
    memory = HypotheticalMemory(tmp_path)
    fact = memory.remember("mkutano wa bodi", "1,0,0")
    hyp = memory.imagine("mkutano wa bodi wa kubuni", "1,0,0", [fact])
    assert [row["id"] for row in memory.recall("1,0,0")] == [fact]
    assert [row["id"] for row in memory.simulate("1,0,0")] == [hyp]
    assert memory.provenance(hyp)["basis"] == [fact]

def test_imagining_needs_a_real_basis(tmp_path):
    memory = HypotheticalMemory(tmp_path)
    with pytest.raises(HypotheticalError, match="basis"):
        memory.imagine("kitu", "1,0", [])
    with pytest.raises(HypotheticalError, match="do not exist"):
        memory.imagine("kitu", "1,0", [99])

def test_promotion_needs_evidence(tmp_path):
    memory = HypotheticalMemory(tmp_path)
    fact = memory.remember("mkutano", "1,0")
    hyp = memory.imagine("mkutano mkubwa", "1,0", [fact])
    with pytest.raises(HypotheticalError, match="evidence"):
        memory.promote(hyp, [])
    with pytest.raises(HypotheticalError, match="do not exist"):
        memory.promote(hyp, [123])
    promoted = memory.promote(hyp, [fact])
    recalled = {row["id"] for row in memory.recall("1,0")}
    assert recalled == {fact, promoted}
    assert memory.provenance(promoted)["kind"] == "promoted"

def test_verify_reports_both_stores(tmp_path):
    memory = HypotheticalMemory(tmp_path)
    fact = memory.remember("a", "1,0")
    memory.imagine("b", "1,0", [fact])
    report = memory.verify()
    assert report["facts"] == 1
    assert report["imagined"] == 1

def test_a_tampered_store_is_reported(tmp_path):
    import json
    memory = HypotheticalMemory(tmp_path)
    memory.remember("a", "1,0")
    db = tmp_path / "facts.db"
    document = json.loads(db.read_text(encoding="utf-8"))
    document["items"][0]["content"] = "imebadilishwa"
    db.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(HypotheticalError):
        HypotheticalMemory(tmp_path).verify()
