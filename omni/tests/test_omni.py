import pytest

from omnishield.omnilang import Lexicon, OmniError, gloss, parse, speak, translate


def test_speak_and_parse_round_trip(tmp_path):
    lexicon = Lexicon(tmp_path / "omni.json")
    for concept in ("person", "see", "sun", "water"):
        lexicon.learn(concept)
    sentence = speak(lexicon, "person", "see", "sun", tense="past", plural=True)
    parsed = parse(lexicon, sentence)
    assert parsed["tense"] == "past"
    assert [item["concept"] for item in parsed["concepts"]] == ["person", "see", "sun"]
    assert parsed["concepts"][0]["plural"] is True
    assert "person" in gloss(lexicon, sentence)
    assert "[past]" in gloss(lexicon, sentence)


def test_roots_are_stable_and_unique(tmp_path):
    first = Lexicon(tmp_path / "a.json")
    second = Lexicon(tmp_path / "b.json")
    assert first.learn("water") == second.learn("water")
    roots = {first.learn(word) for word in ("water", "fire", "earth", "air", "stone", "wind")}
    assert len(roots) == 6
    assert first.root("water") == first.by_concept["water"]


def test_translate_learns_new_words_and_saves(tmp_path):
    path = tmp_path / "omni.json"
    lexicon = Lexicon(path)
    result = translate(lexicon, "person speaks water")
    assert result["words"] == 3
    assert "speaks" in result["learned"]
    assert all(token in lexicon.by_root for token in result["omni"].split())
    lexicon.save()
    reloaded = Lexicon(path)
    assert reloaded.by_concept == lexicon.by_concept
    with pytest.raises(OmniError):
        translate(lexicon, "   ")


def test_errors_are_refused(tmp_path):
    lexicon = Lexicon(tmp_path / "omni.json")
    with pytest.raises(OmniError):
        lexicon.learn("  ")
    with pytest.raises(OmniError):
        lexicon.root("unknown")
    with pytest.raises(OmniError):
        parse(lexicon, "")
    lexicon.learn("person")
    with pytest.raises(OmniError):
        parse(lexicon, "person")
    with pytest.raises(OmniError):
        speak(lexicon, "person", "person", tense="someday")
    with pytest.raises(OmniError):
        Lexicon().save()
