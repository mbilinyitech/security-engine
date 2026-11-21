
import pytest

from omnishield.self_model import (
    SelfError,
    authentic_self,
    existential_awareness,
    future_self,
    ideal_self,
    identity_crisis,
    narrative_identity,
    self_actualisation,
    self_compassion,
    self_confidence,
    self_criticism,
    self_doubt,
    self_esteem,
    self_model,
    social_awareness,
    spatial_awareness,
)


def test_self_model_reports_calibration():
    result = self_model({"vision": 0.8, "speech": 0.4}, observed=0.5)
    assert result["claimed"] == pytest.approx(0.6)
    assert result["strongest"] == "vision"
    assert result["weakest"] == "speech"
    assert "calibration_error" in result
    with pytest.raises(SelfError):
        self_model({})


def test_social_and_spatial_awareness():
    social = social_awareness(
        [
            {"agent": "a", "action": "wait"},
            {"agent": "a", "action": "wait"},
            {"agent": "b", "action": "go"},
            {"agent": "b", "action": "stop"},
        ]
    )
    assert social["agents"] == 2
    assert social["predictability"] == 0.5
    assert 0.5 < social["theory_of_mind"] <= 1.0

    spatial = spatial_awareness(
        {"x": 0.0, "y": 0.0, "theta": 0.0},
        [{"name": "wall", "x": 3.0, "y": 0.0}, {"name": "box", "x": 0.0, "y": 2.0}],
    )
    assert spatial["nearest"] == "box"
    assert spatial["landmarks"][0]["bearing_deg"] == 0.0
    assert spatial["blocked"] is False


def test_existential_awareness_and_criticism():
    assert existential_awareness(0.8, 0.9)["defended_by_meaning"] is True
    assert self_criticism(1, 10)["style"] == "constructive"
    assert self_criticism(8, 10)["style"] == "harsh"
    with pytest.raises(SelfError):
        self_criticism(1, 0)


def test_compassion_esteem_confidence_doubt():
    assert self_compassion(0.9, 0.8, 0.7)["band"] == "warm"
    assert self_esteem(8, 2)["esteem"] > 0.5
    assert self_confidence(0.8, 20)["evidence_weight"] == pytest.approx(1.0)
    assert self_doubt(0, 0.9)["verify_first"] is True
    assert self_doubt(20, 0.9)["doubt"] < 0.1


def test_self_actualisation_and_identity():
    reached = self_actualisation(
        {
            "physiological": 0.9,
            "safety": 0.9,
            "belonging": 0.9,
            "esteem": 0.9,
            "actualisation": 0.8,
        }
    )
    assert reached["actualising"] is True
    assert reached["unmet"] == []
    crisis = identity_crisis({"honesty": 0.9, "speed": 0.8}, {"honesty": 0.3, "speed": 0.75})
    assert crisis["crisis"] is True
    assert crisis["changed"] == ["honesty"]


def test_narrative_future_ideal_and_authentic():
    story = narrative_identity(
        [
            {"valence": 0.8, "agency": 0.9, "chapter": "build"},
            {"valence": 0.6, "agency": 0.8, "chapter": "build"},
        ]
    )
    assert story["tone"] == "upward"
    assert story["theme"] == "build"
    assert story["coherence"] > 0.7

    future = future_self({"skill": 0.2}, {"skill": 0.8}, horizon=0.5)
    assert future["projected"]["skill"] == pytest.approx(0.5)
    assert future["reachable"] is True

    ideal = ideal_self({"skill": 1.0}, {"skill": 0.4})
    assert ideal["largest"] == "skill"
    assert ideal["close"] is False

    assert authentic_self({"honesty": 0.9}, {"honesty": 0.85})["authentic"] is True
    assert authentic_self({"honesty": 0.9}, {"honesty": 0.3})["conflicts"] == ["honesty"]
