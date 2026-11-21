import pytest

from omnishield.reasoning import (
    BeliefState,
    KnowledgeBase,
    LinearSCM,
    ReasoningError,
    abduce,
    analogy,
    causal_effect,
    counterfactual,
    creative_recombine,
    critical_evaluate,
    deduce,
    dialectic,
    fact,
    fuzzy_infer,
    hypotheses,
    induce,
    moral_assess,
    spatial_relation,
    systems_simulate,
    temporal_relation,
)

RAIN, WET, SLIPPERY = fact("rain"), fact("wet"), fact("slippery")


def test_deduction_returns_a_proof():
    kb = KnowledgeBase().tell(RAIN).rule([RAIN], WET).rule([WET], SLIPPERY)
    result = deduce(kb, SLIPPERY)
    assert result["entails"] is True
    assert [step["conclusion"] for step in result["proof"]] == ["slippery", "wet"]
    assert deduce(kb, fact("snow"))["entails"] is False


def test_induction_finds_the_separating_attribute():
    positives = [{"colour": "red", "size": "big"}, {"colour": "red", "size": "small"}]
    negatives = [{"colour": "blue", "size": "big"}]
    result = induce(positives, negatives)
    assert result["pattern"] == {"colour": "red"}
    assert result["support"] == 1.0
    with pytest.raises(ReasoningError):
        induce([])


def test_abduction_ranks_the_explanation_that_covers_more():
    kb = KnowledgeBase().rule([fact("rain")], WET).rule([fact("sprinkler")], WET)
    ranked = abduce(kb, [WET], [fact("rain"), fact("sprinkler")])
    assert {row["explained"] for row in ranked} == {1}
    assert ranked[0]["score"] == 0.9


def test_analogy_maps_shared_structure_and_transfers_the_rest():
    result = analogy({"wings": True, "flies": True}, {"wings": True, "swims": True})
    assert result["mapping"]["wings"]["equal"] is True
    assert result["inferences"] == {"flies": True}
    assert 0 < result["score"] < 1


def test_causal_effect_is_the_product_along_the_path():
    scm = LinearSCM().add("x", "y", 2.0).add("y", "z", 3.0)
    result = causal_effect(scm, "x", "z")
    assert result["effect"] == 6.0
    assert result["paths"][0]["route"] == "x -> y -> z"


def test_counterfactual_keeps_the_noise_and_changes_the_mechanism():
    scm = LinearSCM().add("x", "y", 2.0).add("y", "z", 3.0)
    observed = {"x": 1.0, "y": 2.0, "z": 6.0}
    result = counterfactual(scm, observed, {"x": 2.0}, "z")
    assert result["actual"] == 6.0
    assert result["counterfactual"] == 12.0
    assert result["change"] == 6.0


def test_fuzzy_inference_defuzzifies_to_a_number():
    sets = {"cold": (0.0, 0.0, 0.5), "hot": (0.5, 1.0, 1.0)}
    rules = [({"temp": "cold"}, "cold"), ({"temp": "hot"}, "hot")]
    result = fuzzy_infer(rules, sets, {"temp": 0.9})
    assert result["value"] > 0.8
    assert result["strengths"]["hot"] == pytest.approx(0.8, abs=0.01)


def test_allen_interval_relations():
    assert temporal_relation((1, 2), (3, 4)) == "before"
    assert temporal_relation((1, 2), (2, 3)) == "meets"
    assert temporal_relation((1, 5), (2, 3)) == "contains"
    assert temporal_relation((2, 3), (1, 5)) == "during"
    assert temporal_relation((1, 3), (2, 4)) == "overlaps"
    assert temporal_relation((1, 2), (1, 2)) == "equals"
    with pytest.raises(ReasoningError):
        temporal_relation((2, 1), (0, 1))


def test_box_relations():
    assert spatial_relation((0, 0, 4, 4), (1, 1, 2, 2)) == "contains"
    assert spatial_relation((1, 1, 2, 2), (0, 0, 4, 4)) == "inside"
    assert spatial_relation((0, 0, 1, 1), (2, 2, 3, 3)) == "disjoint"
    assert spatial_relation((0, 0, 2, 2), (2, 0, 4, 2)) == "touching"
    assert spatial_relation((0, 0, 2, 2), (1, 1, 3, 3)) == "overlaps"


def test_second_order_beliefs_and_false_beliefs():
    beliefs = BeliefState().update("alice", "rain")
    beliefs.update_nested("alice", "bob", "rain")
    assert beliefs.believes("alice", "rain") is True
    assert beliefs.believes("bob", "rain") is False
    assert beliefs.nested("alice", "bob") == ["rain"]
    assert beliefs.false_belief("alice", "bob") == ["rain"]


def test_moral_scoring_is_explicit():
    assert moral_assess("poison the well", harm=3, rights=1)["verdict"] == "forbidden"
    assert moral_assess("fund the clinic", utility=3, fairness=1)["verdict"] == "required"
    permitted = moral_assess("delay the launch", harm=0.5, utility=0.4)
    assert permitted["verdict"] in {"permitted", "permitted_with_conditions"}


def test_recombination_scores_novelty_and_coherence():
    concepts = {"lamp": {"light", "stand"}, "phone": {"light", "screen"}, "torch": {"light", "grip"}}
    combos = creative_recombine(concepts, limit=2)
    assert len(combos) == 2
    assert combos[0]["score"] >= combos[1]["score"]
    assert "light" in combos[0]["attributes"]


def test_argument_critique_finds_fallacies():
    weak = critical_evaluate(
        {
            "premises": [{"text": "my neighbour said so", "evidence": False}],
            "conclusion": "all swans are white",
            "sample": 4,
            "attacks": ["you are stupid"],
        }
    )
    assert set(weak["fallacies"]) == {
        "unsupported_premise",
        "hasty_generalisation",
        "ad_hominem",
    }
    assert weak["verdict"] == "fallacious"
    sound = critical_evaluate(
        {"premises": [{"text": "the trial covered 400 patients", "evidence": True}],
         "conclusion": "the drug reduces fever"}
    )
    assert sound["verdict"] == "sound"


def test_systems_simulation_detects_equilibrium_and_growth():
    decay = systems_simulate({"a": {"level": 1.0, "decay": 1.0}}, [], steps=10)
    assert decay["behaviour"] == "equilibrium"
    assert decay["final"]["a"] == 0.0
    growth = systems_simulate({"a": {"level": 1.0, "decay": 0.0}}, [("a", "a", 0.1, 0)], steps=10)
    assert growth["behaviour"] == "growth"
    assert growth["final"]["a"] > 1.0


def test_dialectic_merges_evidence_and_reports_the_rest():
    result = dialectic(
        {"claims": [{"text": "A", "evidence": 1}, {"text": "B", "evidence": 0}]},
        {"claims": [{"text": "A", "evidence": 1}, {"text": "C", "evidence": 0}]},
    )
    assert result["synthesis"] == ["a"]
    assert {row["text"] for row in result["unresolved"]} == {"b", "c"}


def test_hypothesis_generation_names_a_discriminating_test():
    kb = (
        KnowledgeBase()
        .rule([fact("rain")], WET)
        .rule([fact("rain")], fact("clouds"))
        .rule([fact("sprinkler")], WET)
    )
    ranked = hypotheses(kb, [WET, fact("clouds")], [fact("rain"), fact("sprinkler")])
    assert ranked[0]["hypothesis"] == "rain"
    assert ranked[0]["discriminating"] == ["clouds"]
    assert ranked[1]["needs_test"] is True
