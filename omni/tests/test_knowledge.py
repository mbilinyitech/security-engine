import pytest

from omnishield.knowledge import DAY_MS, KnowledgeError, KnowledgeStore


def test_add_deduplicates_and_strengthens(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    first = store.add("Lions live in prides and hunt together", source="a", title="lions", tags=["animals"])
    second = store.add("Lions live in prides and hunt together", source="b")
    assert first["created"] is True
    assert second["created"] is False
    assert second["salience"] > first["salience"]
    assert store.stats()["items"] == 1
    assert store.stats()["repeats"] == 1
    with pytest.raises(KnowledgeError):
        store.add("x", source="a")


def test_search_ranks_by_term_frequency_and_salience(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("lions hunt in prides", source="a", title="lions")
    store.add("rust prevents data races with ownership", source="b", title="rust")
    results = store.search("lions hunt")
    assert results[0]["title"] == "lions"
    assert results[0]["score"] > 0
    assert store.search("ownership")[0]["title"] == "rust"
    with pytest.raises(KnowledgeError):
        store.search("the and of")


def test_decay_follows_the_half_life(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    now = 1_700_000_000_000
    store.add("memory decays with time", source="a", now_ms=now)
    store.decay(now_ms=now + 30 * DAY_MS, half_life_days=30)
    assert store.items[0]["salience"] == pytest.approx(0.25, abs=1e-6)
    store.decay(now_ms=now + 30 * DAY_MS, half_life_days=30)
    assert store.items[0]["salience"] == pytest.approx(0.25, abs=1e-6)
    with pytest.raises(KnowledgeError):
        store.decay(half_life_days=0)


def test_consolidation_merges_near_duplicates_and_prunes(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("alpha beta gamma delta epsilon zeta", source="a")
    store.add("alpha beta gamma delta epsilon zeta eta", source="b")
    store.add("completely different words here entirely", source="c")
    store.items[2]["salience"] = 0.01
    result = store.consolidate()
    assert result["merged"] == 1
    assert result["pruned"] == 1
    assert result["kept"] == 1


def test_spaced_repetition_schedules_reviews(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    now = 1_700_000_000_000
    item = store.add("spaced repetition strengthens memory", source="a", now_ms=now)
    due = store.review(now_ms=now + DAY_MS + 1)
    assert [entry["id"] for entry in due] == [item["id"]]
    graded = store.grade(item["id"], 4, now_ms=now + DAY_MS + 1)
    assert graded["reps"] == 1
    assert graded["interval_days"] == 2
    assert graded["due_ms"] > now + DAY_MS
    failed = store.grade(item["id"], 1, now_ms=now + DAY_MS + 1)
    assert failed["reps"] == 0
    assert failed["interval_days"] == 1
    with pytest.raises(KnowledgeError):
        store.grade(item["id"], 9)
    with pytest.raises(KnowledgeError):
        store.grade("missing", 3)


def test_links_are_hebbian_cooccurrence(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("neurons that fire together wire together", source="a")
    store.add("fire together makes wiring stronger", source="b")
    pairs = {(entry["a"], entry["b"]) for entry in store.links(top=10)}
    assert ("fire", "together") in pairs


def test_store_persists_and_reports_stats(tmp_path):
    path = tmp_path / "k.jsonl"
    store = KnowledgeStore.open(path)
    store.add("persistent knowledge survives a reload", source="a", tags=["memory"])
    store.add("another fact about memory and reload", source="b", tags=["memory"])
    reloaded = KnowledgeStore.open(path)
    assert len(reloaded.items) == 2
    stats = reloaded.stats()
    assert stats["items"] == 2
    assert stats["sources"] == 2
    assert stats["top_tags"][0][0] == "memory"
    assert path.stat().st_mode & 0o777 == 0o600
    assert stats["oldest_ms"] <= stats["newest_ms"]
