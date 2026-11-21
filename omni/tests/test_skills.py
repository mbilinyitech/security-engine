import pytest

from omnishield.knowledge import KnowledgeStore
from omnishield.skills import SKILLS, SkillError, registry, run


def test_registry_is_introspectable():
    entries = registry()
    assert len(entries) >= 12
    names = [entry["name"] for entry in entries]
    assert names == sorted(names)
    for entry in entries:
        assert entry["summary"] and isinstance(entry["parameters"], dict)
        assert entry["examples"]
    assert "answer" in SKILLS and "pathtrace" in SKILLS


def test_run_answer_and_language(tmp_path):
    store_path = tmp_path / "k.jsonl"
    store = KnowledgeStore.open(store_path)
    store.add("BM25 ranks passages with term frequency and inverse document frequency.", source="doc", title="ranking")
    result = run("answer", {"question": "how does bm25 rank", "store": str(store_path)})
    assert result["ok"] is True
    assert result["skill"] == "answer"
    assert result["result"]["citations"]
    assert result["latency_ms"] >= 0
    language = run("language", {"text": "habari ya asubuhi na watu"})
    assert language["result"]["language"] == "sw"


def test_bad_input_is_refused():
    with pytest.raises(SkillError):
        run("missing", {})
    with pytest.raises(SkillError):
        run("answer", {})
    with pytest.raises(SkillError):
        run("language", {"text": "hello", "unknown": 1})
    with pytest.raises(SkillError):
        run("language", {})
