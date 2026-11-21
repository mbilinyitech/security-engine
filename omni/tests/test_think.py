import pytest

from omnishield.knowledge import KnowledgeStore
from omnishield.think import ThinkError, contradictions, sub_questions, think


def _store(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("The path tracer bounces light and never uses a texture cache.", source="a")
    store.add("The path tracer bounces light and uses a texture cache.", source="b")
    store.add("BM25 ranks passages by term frequency.", source="c")
    return store


def test_think_reports_coverage_and_disagreement(tmp_path):
    store = _store(tmp_path)
    result = think("how does the path tracer bounce light", store, depth=3)
    assert result["confidence"] > 0
    assert 0 < result["coverage"] <= 1
    assert result["steps"][-1]["step"] == "answer"
    assert len(result["contradictions"]) == 1
    assert result["citations"]
    assert result["latency_ms"] >= 0


def test_helpers_and_errors(tmp_path):
    store = _store(tmp_path)
    assert sub_questions("how does light bounce", limit=2) == [
        "what is said about how",
        "what is said about does",
    ]
    assert contradictions([]) == []
    with pytest.raises(ThinkError):
        think("light", store, depth=0)
    with pytest.raises(ThinkError):
        think("the and of", store)
    with pytest.raises(ThinkError):
        think("light", KnowledgeStore.open(tmp_path / "empty.jsonl"))
