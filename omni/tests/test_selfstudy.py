import pytest

from omnishield.knowledge import KnowledgeStore
from omnishield.omnilang import Lexicon
from omnishield.selfstudy import lesson, run, top_terms


def test_lesson_learns_roots_and_cites(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("BM25 ranks passages with term frequency and inverse document frequency.", source="doc", title="ranking")
    lexicon = Lexicon(tmp_path / "lex.json")
    record = lesson(store, lexicon, {"text": "BM25 ranks passages with term frequency.", "source": "doc"})
    assert "bm25" in record["terms"]
    assert record["new_roots"]
    assert record["cited"] is True
    assert len(store.items) == 2
    assert lexicon.path is not None and lexicon.save().is_file()


def test_curriculum_grows_and_refuses_empty(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("A path tracer bounces light to produce global illumination.", source="doc", title="render")
    passages = [{"text": "A path tracer bounces light to produce global illumination.", "source": "doc"}]
    result = run(passages, store, Lexicon(tmp_path / "lex.json"), rounds=2)
    assert result["lessons"] == 2
    assert result["lexicon"] > 0
    assert result["hit_rate"] > 0
    assert top_terms("") == []
    with pytest.raises(ValueError):
        run([], store, Lexicon(tmp_path / "x.json"))
    with pytest.raises(ValueError):
        run(passages, store, Lexicon(tmp_path / "y.json"), rounds=0)
    with pytest.raises(ValueError):
        lesson(store, Lexicon(tmp_path / "z.json"), {"text": ""})
