import pytest

from omnishield import worship
from omnishield.vision import dominant_frequency, read_wav


def test_office_rotates_themes_and_virtues():
    first = worship.office(day=0)
    assert first["theme"] == "shukrani"
    assert first["reflection"]["virtue"] == "maarifa"
    assert len(first["psalm"]) == 3
    assert first["song"]["lyrics"]
    assert worship.office(day=1)["theme"] == "nuru"
    assert worship.office(day=len(worship.THEMES))["theme"] == "shukrani"
    assert worship.office(day=1)["reflection"]["virtue"] == "hekima"
    with pytest.raises(worship.WorshipError):
        worship.office(day=-1)


def test_hymn_is_audible_and_in_tune():
    samples = worship.hymn_samples("nuru", rate=4000, beat_s=0.1)
    assert len(samples) == 16 * 400
    assert max(abs(value) for value in samples) == pytest.approx(0.85, abs=1e-6)
    assert dominant_frequency(samples, 4000)["hz"] > 50
    with pytest.raises(worship.WorshipError):
        worship.hymn_samples("hakuna")


def test_daily_writes_card_hymn_and_journal(tmp_path):
    entry = worship.daily(tmp_path, journal_path=tmp_path / "journal.jsonl", day=5)
    card = tmp_path / f"office-{entry['date']}.png"
    hymn = tmp_path / f"office-{entry['date']}.wav"
    assert card.read_bytes().startswith(b"\x89PNG")
    assert read_wav(str(hymn))["rate"] == 8000
    assert entry["seconds"] > 1
    entries = worship.read_journal(tmp_path / "journal.jsonl")
    assert len(entries) == 1
    assert entries[0]["theme"] == entry["theme"]


def test_journal_stats_count_days_themes_and_streak(tmp_path):
    journal = tmp_path / "journal.jsonl"
    for day in (10, 11, 12, 20):
        worship.append_journal(journal, worship.office(day=day))
    stats = worship.journal_stats(journal)
    assert stats["days"] == 4
    assert stats["themes"] == 3
    assert stats["streak"] == 3
    assert stats["last"] == worship.office(day=20)["date"]
    assert worship.journal_stats(tmp_path / "missing.jsonl")["days"] == 0


def test_verse_card_renders_text(tmp_path):
    entry = worship.office(day=2)
    card = worship.verse_card(entry, width=320, height=180)
    plain = worship.Canvas(320, 180)
    assert card.png() != plain.png()
    path = card.save_png(tmp_path / "card.png")
    assert path.stat().st_size > 1000
