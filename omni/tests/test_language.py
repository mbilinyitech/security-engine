import pytest

from omnishield.knowledge import KnowledgeStore
from omnishield.language import ConversationTracker, LanguageError, identify


def test_identifies_swahili_english_and_scripts():
    swahili = identify("habari ya asubuhi na watu wa nyumbani")
    assert swahili["language"] == "sw"
    assert swahili["confidence"] > 0.5
    assert swahili["runner_up"] != "sw"
    english = identify("the quick brown fox is in the house")
    assert english["language"] == "en"
    assert identify("你好世界")["method"] == "script"
    assert identify("кот в доме с детьми")["language"] == "ru"
    with pytest.raises(LanguageError):
        identify("   ")
    with pytest.raises(LanguageError):
        identify("1234 5678")


def test_tracker_counts_languages_and_drift():
    tracker = ConversationTracker(window=2)
    tracker.observe("A", "habari ya asubuhi na watu", at=1)
    tracker.observe("B", "tunazungumza kuhusu mchanga na maji", at=2)
    tracker.observe("A", "the rendering uses bm25 retrieval and matrices", at=3)
    summary = tracker.summary()
    assert summary["lines"] == 3
    assert summary["languages"]["sw"] == 2
    assert summary["languages"]["en"] == 1
    assert summary["speakers"]["A"] == 2
    assert summary["mean_drift"] > 0
    assert summary["topics"]
    with pytest.raises(LanguageError):
        tracker.observe("  ", "habari")
    with pytest.raises(LanguageError):
        ConversationTracker(window=1)


def test_tracker_learns_into_the_store(tmp_path):
    tracker = ConversationTracker(window=2)
    tracker.observe("A", "habari ya asubuhi na watu")
    tracker.observe("B", "the renderer uses matrices")
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    learned = tracker.learn(store)
    assert learned["lines"] == 2
    assert len(store.items) == 1
    assert "conversation" in learned["text"].lower()
    with pytest.raises(LanguageError):
        ConversationTracker().learn(store)
