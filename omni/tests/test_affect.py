import pytest

from omnishield.affect import (
    AffectError,
    big_five,
    compassion,
    contagion,
    despair,
    emotional_intelligence,
    empathy,
    envy,
    express,
    forgiveness,
    gratitude,
    guilt,
    hate,
    hope,
    jealousy,
    love,
    pride,
    recognise,
    resentment,
    shame,
    sympathy,
)


def test_big_five_normalises_and_names_the_extremes():
    result = big_five(
        {
            "openness": [5, 4],
            "conscientiousness": [3, 3],
            "extraversion": [2, 2],
            "agreeableness": [4, 4],
            "neuroticism": [2, 3],
        }
    )
    assert result["profile"]["openness"] == 87.5
    assert result["dominant"] == "openness"
    assert result["lowest"] == "extraversion"
    assert big_five({"openness": [3]})["profile"]["neuroticism"] == 50.0
    with pytest.raises(AffectError):
        big_five({"courage": [3]})
    with pytest.raises(AffectError):
        big_five({"openness": [9]})


def test_expression_and_recognition():
    assert express("joy", 0.9)["label"] == "strongly"
    assert express("joy", 0.1)["label"] == "barely"
    found = recognise("happy and glad, nimefurahi")
    assert found["emotion"] == "joy"
    assert found["confidence"] == 1.0
    assert recognise("the table is here")["emotion"] == "neutral"
    with pytest.raises(AffectError):
        express("smug", 0.5)


def test_contagion_and_emotional_intelligence():
    spread = contagion("fear", 0.8, 0.9)
    assert spread["transmitted"] > 0.5
    assert spread["threshold_met"] is True
    score = emotional_intelligence(
        {"perceiving": 0.8, "understanding": 0.7, "managing": 0.6, "using": 0.75}
    )
    assert score["band"] == "high"
    assert score["weakest"] == "managing"
    with pytest.raises(AffectError):
        emotional_intelligence({"perceiving": 1.0})


def test_empathy_sympathy_compassion():
    assert empathy(0.9, 0.3)["kind"] == "cognitive"
    assert empathy(0.5, 0.5)["total"] == 0.5
    assert sympathy(0.8, 0.7)["moved"] is True
    assert compassion(0.9, 0.9)["action"] == "help"
    assert compassion(0.9, 0.9, cost=1.0)["compassion"] < 0.5


def test_forgiveness_resentment_and_gratitude():
    assert forgiveness(0.1, 0.9)["forgiven"] is True
    assert forgiveness(0.9, 0.0)["forgiven"] is False
    assert resentment(0.9, 0.9)["bitter"] is True
    assert resentment(0.9, 0.9, days=365)["resentment"] < 0.2
    assert gratitude(0.9, 0.8)["expressed"] is True


def test_envy_jealousy_pride():
    assert envy(0.8)["kind"] == "benign"
    assert envy(0.8, benign=False)["motivation"] == "pull_down"
    assert jealousy(0.9, 0.9)["alarm"] is True
    assert pride(0.9, 0.9)["kind"] == "authentic"
    assert pride(0.9, 0.1)["kind"] == "hubristic"


def test_shame_guilt_hope_despair():
    assert shame(0.9, 0.9)["withdraw"] is True
    assert guilt(0.8, 0.9)["repair"] is True
    assert hope(0.8, 0.7, 0.6)["hopeful"] is True
    assert despair(0.9, 0.1)["risk"] is True
    assert despair(0.9, 1.0)["despair"] < 0.5


def test_love_and_hate():
    assert love(0.9, 0.9, 0.9)["kind"] == "consummate"
    assert love(0.9, 0.2, 0.9)["kind"] == "companionate"
    assert love(0.1, 0.1, 0.1)["kind"] == "none"
    assert hate(0.9, 0.9)["dangerous"] is True
