import pytest

from omnishield.ethics import (
    EthicsError,
    animal_welfare,
    beneficence,
    civil_disobedience,
    conflict_of_interest,
    environmental_footprint,
    fairness,
    future_generations,
    justice,
    moral_courage,
    moral_evolution,
    moral_learning,
    non_discrimination,
    resolve_dilemma,
    whistleblowing,
)


def test_dilemma_ranking_picks_the_highest_scoring_option():
    result = resolve_dilemma(
        [
            {"name": "poison", "harm": 3, "rights": 1},
            {"name": "fund", "utility": 2, "fairness": 1},
        ]
    )
    assert result["chosen"] == "fund"
    assert result["ranking"][0]["score"] > result["ranking"][1]["score"]
    with pytest.raises(EthicsError):
        resolve_dilemma([])


def test_beneficence_weighs_gain_against_risk():
    assert beneficence([2, 3], [1])["verdict"] == "act"
    assert beneficence([1], [10])["verdict"] == "do_not_act"
    assert beneficence([1], [1], risk_weight=1.0)["verdict"] == "neutral"


def test_justice_is_a_gini_coefficient():
    assert justice([1, 1, 1, 1])["gini"] == 0.0
    concentrated = justice([10, 0, 0, 0])
    assert concentrated["gini"] == pytest.approx(0.75, abs=0.01)
    assert concentrated["verdict"] == "concentrated"


def test_fairness_reports_the_parity_gap():
    assert fairness({"a": 0.5, "b": 0.45})["verdict"] == "fair"
    assert fairness({"a": 0.8, "b": 0.2})["verdict"] == "unfair"


def test_non_discrimination_applies_the_four_fifths_rule():
    result = non_discrimination({"a": {"selected": 80, "total": 100}, "b": {"selected": 40, "total": 100}})
    assert result["ratio"] == 0.5
    assert result["verdict"] == "fails"
    assert result["flagged"] == ["b"]


def test_environmental_footprint_accounts_and_compares():
    result = environmental_footprint({"car": {"amount": 100, "kg_per_unit": 0.2}}, budget_kg=10)
    assert result["total_kg"] == 20.0
    assert result["verdict"] == "over_budget"
    assert result["over_by_kg"] == 10.0


def test_future_generations_exposes_the_discount_weight():
    undiscounted = future_generations(100, years=10, discount_rate=0.0)
    assert undiscounted["present_value"] == 1100.0
    assert undiscounted["verdict"] == "near_zero_discount"
    discounted = future_generations(100, years=10, discount_rate=0.05)
    assert discounted["weight_at_horizon"] < 1.0
    assert discounted["present_value"] < 1100.0


def test_animal_welfare_weights_harm_by_sentience():
    result = animal_welfare([{"name": "cull", "sentience": 1.0, "harm": 3.0}])
    assert result["total"] == 3.0
    assert result["verdict"] == "significant"


def test_conflict_of_interest_is_detected_from_affiliations():
    affiliations = {"amina": {"bank", "ngo"}, "juma": {"bank"}}
    result = conflict_of_interest(affiliations, "amina", ["juma", "ngo"])
    assert result["conflict"] is True
    assert result["exposed"][0]["shared"] == ["bank"]
    assert result["recommendation"] == "recuse"


def test_whistleblowing_escalates_only_after_internal_channels():
    early = whistleblowing(severity=0.9, evidence=0.9, channels_exhausted=False)
    assert early["action"] == "raise_internally"
    late = whistleblowing(severity=0.9, evidence=0.9, channels_exhausted=True)
    assert late["action"] == "escalate_externally"


def test_civil_disobedience_checklist():
    full = {
        "injustice": True,
        "last_resort": True,
        "proportionate": True,
        "nonviolent": True,
        "accepts_penalty": True,
    }
    assert civil_disobedience(full)["verdict"] == "justified"
    partial = dict(full, last_resort=False)
    assert civil_disobedience(partial)["verdict"] == "partial"


def test_moral_courage_trades_principle_against_cost():
    brave = moral_courage(principle_strength=1.0, personal_cost=0.4, social_pressure=0.5)
    assert brave["act"] is True
    quiet = moral_courage(principle_strength=0.2, personal_cost=1.0, social_pressure=1.0)
    assert quiet["act"] is False


def test_moral_learning_moves_weights_with_feedback():
    result = moral_learning([0.0, 0.0], [1.0, 1.0], feedback=1.0, lr=0.1)
    assert result["weights"] == [0.1, 0.1]
    assert result["score_after"] > result["score_before"]


def test_moral_evolution_keeps_the_best_and_reports_history():
    result = moral_evolution(
        [[1.0, 0.0], [0.0, 1.0], [0.5, 0.5], [0.2, 0.1]],
        [1.0, 1.0],
        generations=5,
        seed=3,
    )
    assert result["best_fitness"] >= 1.0
    assert len(result["history"]) == 5
