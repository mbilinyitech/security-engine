import pytest

from omnishield.interface import (
    ConsentLedger,
    InterfaceError,
    Personalizer,
    UserModel,
    contrast_ratio,
    controllability,
    explain,
    interruptibility,
    minimise,
    readability,
    retention_expired,
)


def test_personaliser_learns_from_feedback_and_ranks():
    model = Personalizer(learning_rate=0.5)
    first = model.update([1.0, 0.0], rating=1.0)
    assert first["error"] == 1.0
    assert first["weights"] == [0.5, 0.0]
    second = model.update([1.0, 0.0], rating=1.0)
    assert second["weights"][0] > first["weights"][0]
    ranked = model.rank({"a": [1.0, 0.0], "b": [0.0, 1.0]})
    assert ranked[0]["item"] == "a"
    with pytest.raises(InterfaceError):
        model.update([1.0], 2.0)


def test_user_model_tracks_skill_from_outcomes():
    model = UserModel()
    model.observe("wifi", True)
    model.observe("wifi", True)
    model.observe("wifi", False)
    assert model.proficiency("wifi") == pytest.approx(0.667, abs=0.01)
    model.observe("python", False)
    summary = model.summary()
    assert summary["strongest"] == "wifi"
    assert summary["weakest"] == "python"


def test_interruptibility_weights_phase_and_urgency():
    focused = interruptibility("focus", urgency=0.1)
    assert focused["recommendation"] == "wait"
    urgent = interruptibility("focus", urgency=1.0, deadline_s=30)
    assert urgent["cost"] < focused["cost"]
    assert urgent["recommendation"] == "interrupt"
    assert interruptibility("idle", urgency=0.0)["cost"] == pytest.approx(0.1)
    with pytest.raises(InterfaceError):
        interruptibility("sleeping", urgency=0.5)


def test_contrast_ratio_follows_wcag():
    black_on_white = contrast_ratio([0, 0, 0], [255, 255, 255])
    assert black_on_white["ratio"] == pytest.approx(21.0, abs=0.1)
    assert black_on_white["aaa_normal"] is True
    grey_on_white = contrast_ratio([150, 150, 150], [255, 255, 255])
    assert grey_on_white["aa_normal"] is False


def test_readability_scores_plain_and_hard_text():
    plain = readability("The cat sat on the mat. The dog ran fast. We like them.")
    assert plain["verdict"] == "plain"
    hard = readability(
        "Notwithstanding the aforementioned considerations, the implementation "
        "necessitates comprehensive reconfiguration of infrastructural dependencies."
    )
    assert hard["flesch"] < plain["flesch"]
    with pytest.raises(InterfaceError):
        readability("   ")


def test_explanation_lists_feature_contributions():
    result = explain([2.0, -1.0, 0.5], [1.0, 1.0, 1.0])
    assert result["score"] == 1.5
    assert result["dominant"] == 0
    assert result["reasons"][0]["direction"] == "supports"
    assert result["reasons"][1]["direction"] == "opposes"
    with pytest.raises(InterfaceError):
        explain([1.0], [1.0, 2.0])


def test_controllability_honours_deny_and_confirmation():
    policy = {"allow": ["read", "write", "delete"], "deny": ["delete"], "require_confirmation": ["write"]}
    assert controllability("read", policy) == {
        "allowed": True,
        "confirmation_required": False,
        "reason": "permitted",
    }
    assert controllability("write", policy)["confirmation_required"] is True
    assert controllability("delete", policy)["allowed"] is False
    assert controllability("deploy", policy)["allowed"] is False


def test_consent_scopes_and_data_minimisation():
    ledger = ConsentLedger()
    ledger.grant("amina", "analytics", {"read"})
    assert ledger.check("amina", "analytics", "read")["allowed"] is True
    assert ledger.check("amina", "analytics", "share")["allowed"] is False
    ledger.grant("amina", "analytics", {"share"})
    assert ledger.check("amina", "analytics", "share")["allowed"] is True
    ledger.withdraw("amina", "analytics")
    assert ledger.check("amina", "analytics", "read")["allowed"] is False

    record = {"name": "amina", "phone": "0700", "note": "x"}
    kept = minimise(record, {"name", "note"})
    assert kept["record"] == {"name": "amina", "note": "x"}
    assert kept["dropped"] == ["phone"]

    assert retention_expired(0, 10 * 86_400, days=30)["expired"] is False
    assert retention_expired(0, 40 * 86_400, days=30)["expired"] is True
