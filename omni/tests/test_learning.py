import pytest

from omnishield.learning import (
    LearningError,
    active_select,
    adversarial_example,
    attribute_classify,
    behavioural_clone,
    competitive_update,
    continual_update,
    curriculum_order,
    epsilon_greedy_bandit,
    federated_average,
    fine_tune,
    intrinsic_reward,
    kmeans,
    knn_predict,
    markov_next,
    masked_predict,
    meta_learning_rate,
    naive_bayes,
    one_shot_match,
    perceptron,
    prototype_classify,
    q_learning,
    shape_reward,
    triplet_loss,
)

CLUSTERS = [[0.0, 0.0], [0.1, 0.1], [5.0, 5.0], [5.1, 5.1]]
CLUSTER_LABELS = ["a", "a", "b", "b"]


def test_knn_classifies_from_neighbours():
    result = knn_predict(CLUSTERS, CLUSTER_LABELS, [0.05, 0.05], k=3)
    assert result["label"] == "a"
    assert result["confidence"] > 0.5
    with pytest.raises(LearningError):
        knn_predict([], [], [0, 0])


def test_kmeans_finds_the_two_clusters():
    result = kmeans(CLUSTERS, 2, seed=1)
    assert result["assignments"] == [0, 0, 1, 1] or result["assignments"] == [1, 1, 0, 0]
    assert result["inertia"] < 0.1
    with pytest.raises(LearningError):
        kmeans(CLUSTERS, 9)


def test_q_learning_prefers_the_rewarding_action():
    transitions = [("s", "bad", 0.0, "t", True), ("s", "good", 1.0, "t", True)]
    result = q_learning(transitions, alpha=1.0, gamma=0.9)
    assert result["policy"]["s"] == "good"
    assert result["values"]["s/good"] == 1.0


def test_masked_prediction_recovers_a_linear_relation():
    rows = [[1.0, 2.0], [2.0, 4.0], [3.0, 6.0]]
    result = masked_predict(rows, 1)
    assert result["slope"] == pytest.approx(2.0, abs=0.01)
    assert result["mse"] < 0.01


def test_behavioural_cloning_copies_demonstrations():
    demos = [([0.0, 0.0], "left"), ([0.1, 0.0], "left"), ([5.0, 5.0], "right"), ([5.1, 5.0], "right")]
    result = behavioural_clone(demos)
    assert result["leave_one_out_accuracy"] == 1.0


def test_markov_model_predicts_the_next_symbol():
    result = markov_next(["a", "b", "a", "b"], "a")
    assert result["next"] == "b"
    assert result["distribution"] == {"b": 1.0}


def test_bandit_finds_the_best_arm_and_reports_regret():
    result = epsilon_greedy_bandit([0.2, 0.8], steps=300, epsilon=0.1, seed=0)
    assert result["best_arm"] == 1
    assert result["regret"] < 120


def test_transfer_learning_improves_on_the_new_task():
    result = fine_tune([0.0, 0.0], [[1.0], [2.0], [3.0]], [1, 1, 1], lr=0.5, steps=60)
    assert result["improved"] is True
    assert result["loss_after"] < result["loss_before"]


def test_meta_learning_picks_a_rate_from_the_grid():
    tasks = [
        ([[1.0], [2.0]], [1, 1]),
        ([[1.0, 0.0], [0.0, 1.0]], [1, 0]),
    ]
    result = meta_learning_rate(tasks)
    assert result["best_rate"] in (0.01, 0.05, 0.1, 0.3, 0.6)
    assert len(result["results"]) == 5


def test_continual_update_stays_near_the_previous_weights():
    loose = continual_update([1.0, 1.0], [0.0, 0.0], [[1.0, 1.0]], [1], ewc_lambda=0.0)
    tight = continual_update([1.0, 1.0], [0.0, 0.0], [[1.0, 1.0]], [1], ewc_lambda=50.0)
    assert tight["drift_from_previous"] <= loose["drift_from_previous"]


def test_curriculum_orders_and_compares_losses():
    rows = [[0.1], [5.0], [0.2], [5.1]]
    labels = [0, 1, 0, 1]
    result = curriculum_order(rows, labels)
    assert sorted(result["order"]) == [0, 1, 2, 3]
    assert "curriculum_loss" in result and "baseline_loss" in result


def test_active_learning_picks_the_most_uncertain_point():
    result = active_select([[0.5, 0.0], [5.0, 0.0], [-5.0, 0.0]], [1.0, 0.0], k=1)
    assert result["chosen"] == [0]


def test_federated_average_weights_by_samples():
    clients = [{"weights": [0.0, 0.0], "samples": 1}, {"weights": [2.0, 2.0], "samples": 3}]
    result = federated_average(clients)
    assert result["weights"] == [1.5, 1.5]
    assert result["max_divergence"] == pytest.approx(2.1213, abs=0.01)


def test_competitive_learning_updates_only_the_winner():
    result = competitive_update([[1.0, 0.0], [0.0, 1.0]], [1.0, 0.0])
    assert result["winner"] == 0
    assert result["weights"][1] == [0.0, 1.0]


def test_adversarial_example_moves_the_prediction():
    result = adversarial_example([1.0], [-1.0], 0, epsilon=2.0)
    assert result["clean_probability"] < 0.5
    assert result["adversarial_probability"] > 0.5
    assert result["flipped"] is True


def test_triplet_loss_pulls_and_pushes():
    result = triplet_loss([0.0, 0.0], [1.0, 0.0], [1.0, 1.0], margin=1.0, lr=0.1)
    assert result["loss_after"] < result["loss_before"]


def test_gaussian_naive_bayes_separates_two_classes():
    rows = [[0.0, 0.0], [0.1, 0.1], [5.0, 5.0], [5.1, 5.1]]
    result = naive_bayes(rows, [0, 0, 1, 1])
    assert result["accuracy"] == 1.0
    assert result["predictions"] == [0, 0, 1, 1]


def test_perceptron_learns_a_separating_line():
    result = perceptron([[0.0, 1.0], [0.0, 2.0], [5.0, 5.0], [5.0, 6.0]], [0, 0, 1, 1])
    assert result["accuracy"] == 1.0
    assert result["mistakes"] > 0


def test_prototypes_and_attribute_matching():
    support = {"a": [[0.0, 0.0], [0.2, 0.0]], "b": [[5.0, 5.0]]}
    assert prototype_classify(support, [0.1, 0.0])["label"] == "a"
    classes = {"cat": [1.0, 0.0, 0.0], "dog": [0.0, 1.0, 0.0]}
    assert attribute_classify(classes, [0.9, 0.1, 0.0])["label"] == "cat"


def test_one_shot_matching_accepts_and_rejects():
    accepted = one_shot_match(([0.0, 0.0], "cat"), [0.1, 0.0], threshold=1.0)
    rejected = one_shot_match(([0.0, 0.0], "cat"), [5.0, 5.0], threshold=1.0)
    assert accepted["label"] == "cat" and accepted["accepted"] is True
    assert rejected["label"] is None and rejected["accepted"] is False


def test_reward_shaping_and_curiosity_bonus():
    shaped = shape_reward([1.0, 1.0, 1.0], [0.0, 1.0, 2.0, 3.0], gamma=0.9)
    assert shaped["shaped"] == [1.9, 1.8, 1.7]
    assert shaped["total_shaped"] == pytest.approx(5.4, abs=0.01)
    bonus = intrinsic_reward([0.5, 2.0], [1.0, 1.0])
    assert bonus["bonuses"] == [0.5, 1.0]
    assert bonus["mean"] == 0.75
