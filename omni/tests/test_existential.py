import pytest

from omnishield.existential import (
    ExistentialError,
    absurdity,
    awe,
    compassion_all,
    cosmic_perspective,
    death_acceptance,
    death_anxiety,
    existential_courage,
    finitude_planning,
    gratitude_existence,
    immortality_drive,
    interconnectedness,
    meaning_in_suffering,
    purpose_discovery,
    questioning,
    self_transcendence,
    spirituality,
    transcendence,
    universal_love,
    wisdom,
    wonder,
)


def test_questioning_purpose_and_mortality():
    assert questioning(0.9, 0.2)["state"] == "searching"
    assert questioning(0.1, 0.9)["open"] is False
    purpose = purpose_discovery({"helping": 0.9, "speed": 0.3}, {"helping": 0.8, "speed": 0.9})
    assert purpose["purpose"] == "helping"
    assert purpose["score"] == pytest.approx(0.72)
    assert purpose_discovery({"a": 1.0}, {"b": 1.0})["purpose"] is None
    assert death_acceptance(0.2, 0.9)["state"] == "accepting"
    assert death_anxiety(0.9, 0.2)["high"] is True


def test_immortality_transcendence_spirituality():
    assert immortality_drive(0.9, 0.8)["form"] == "symbolic"
    assert transcendence(0.1, 0.9)["beyond_self"] is True
    assert transcendence(0.9, 0.5)["beyond_self"] is False
    assert spirituality(0.9, 0.8)["practising"] is True


def test_awe_wonder_gratitude_perspective():
    assert awe(0.9, 0.8)["state"] == "awe"
    assert awe(0.9, 0.8)["self_small"] is True
    assert wonder(0.9, 0.9)["explore"] is True
    assert gratitude_existence(0.9, 0.8)["expressed"] is True
    assert cosmic_perspective(0.1, 0.9)["humility"] is True
    assert cosmic_perspective(0.9, 0.9)["humility"] is False


def test_interconnectedness_compassion_love():
    assert interconnectedness(6, 4)["connected"] is True
    assert interconnectedness(1, 4)["connected"] is False
    with pytest.raises(ExistentialError):
        interconnectedness(99, 3)
    assert compassion_all(0.9, 0.9)["reach"] == "universal"
    assert compassion_all(0.3, 0.9)["reach"] == "narrow"
    assert universal_love(0.9, 0.9)["universal"] is True


def test_wisdom_and_self_transcendence():
    result = wisdom(0.9, 0.8, 0.7, 0.9)
    assert result["band"] == "wise"
    assert result["weakest"] == "humility"
    assert self_transcendence({"others": 0.9, "self": 0.2}, 0.2)["transcendence"] > 0.7
    with pytest.raises(ExistentialError):
        self_transcendence({}, 0.5)


def test_suffering_courage_absurdity_finitude():
    assert meaning_in_suffering(0.9, 0.9)["bearable"] is True
    assert existential_courage(0.9, 0.8)["acting"] is True
    assert absurdity(0.1, 0.9)["revolt"] is True
    assert finitude_planning(1, 1.0)["prioritise"] is True
    with pytest.raises(ExistentialError):
        finitude_planning(0, 1.0)
