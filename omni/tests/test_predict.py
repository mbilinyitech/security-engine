import pytest

from omnishield.predict import (
    PredictError,
    brier_score,
    calibration_report,
    counterfactual,
    detect_anomaly,
    ewma,
    fuse,
    linear_forecast,
    predict_system,
    reality_check,
    sample_system,
)


def test_ewma_smooths_and_projects():
    result = ewma([1, 2, 3, 4, 5], alpha=0.5)
    assert len(result["smoothed"]) == 5
    assert result["next"] == pytest.approx(4.0625)
    assert ewma([7])["next"] == 7.0
    with pytest.raises(PredictError):
        ewma([])
    with pytest.raises(PredictError):
        ewma([1, 2], alpha=0)


def test_linear_forecast_recovers_a_perfect_line():
    model = linear_forecast([1, 2, 3, 4, 5], horizon=2)
    assert model["slope"] == 1.0
    assert model["r2"] == 1.0
    assert model["forecast"] == [6.0, 7.0]
    assert model["direction"] == "up"
    assert linear_forecast([5, 4, 3])["direction"] == "down"
    with pytest.raises(PredictError):
        linear_forecast([1])
    with pytest.raises(PredictError):
        linear_forecast([1, 2], horizon=0)


def test_brier_score_rewards_skill():
    good = brier_score([0.9, 0.1, 0.8], [1, 0, 1])
    bad = brier_score([0.1, 0.9, 0.2], [1, 0, 1])
    assert good["brier"] < bad["brier"]
    assert good["better_than_climatology"] is True
    assert good["skill"] > 0
    with pytest.raises(PredictError):
        brier_score([0.5], [1, 0])
    with pytest.raises(PredictError):
        brier_score([1.5], [1])


def test_calibration_bins_and_ece():
    perfect = calibration_report([0.9] * 5 + [0.1] * 5, [1] * 5 + [0] * 5)
    assert perfect["ece"] == pytest.approx(0.1)
    assert perfect["well_calibrated"] is True
    wrong = calibration_report([0.9] * 5 + [0.1] * 5, [0] * 5 + [1] * 5)
    assert wrong["ece"] == pytest.approx(0.9)
    assert wrong["well_calibrated"] is False
    assert sum(bucket["n"] for bucket in wrong["bins"]) == 10


def test_anomaly_detection_uses_median_and_mad():
    spike = detect_anomaly(100.0, [1, 2, 3, 4, 5])
    assert spike["anomaly"] is True
    assert spike["direction"] == "high"
    assert spike["method"] == "mad"
    assert detect_anomaly(3.0, [1, 2, 3, 4, 5])["anomaly"] is False
    with pytest.raises(PredictError):
        detect_anomaly(1.0, [1, 2])


def test_reality_check_scores_a_prediction():
    close = reality_check({"a": 1.0, "b": 2.0}, {"a": 1.02, "b": 2.03})
    assert close["verdict"] == "close"
    assert close["mae"] < 0.1
    off = reality_check({"a": 1.0}, {"a": 5.0})
    assert off["verdict"] == "off"
    assert off["keys"]["a"]["relative"] == 4.0
    with pytest.raises(PredictError):
        reality_check({"a": 1.0}, {"b": 2.0})


def test_counterfactual_and_fusion():
    added = counterfactual([1, 2, 3], intervention=2, horizon=2)
    assert added["factual"] == [4.0, 5.0]
    assert added["counterfactual"] == [6.0, 7.0]
    multiplied = counterfactual([1, 2, 3], intervention=2, horizon=1, mode="multiply")
    assert multiplied["counterfactual"] == [8.0]
    with pytest.raises(PredictError):
        counterfactual([1, 2], intervention=1, mode="magic")

    fused = fuse([{"value": 10, "sigma": 1}, {"value": 12, "sigma": 2}])
    assert fused["estimate"] == pytest.approx(10.4)
    assert fused["sigma"] == pytest.approx(0.8944, abs=1e-4)
    with pytest.raises(PredictError):
        fuse([])
    with pytest.raises(PredictError):
        fuse([{"value": 1, "sigma": 0}])


def test_system_prediction_is_scored_against_a_real_reading():
    samples = sample_system(3)
    assert len(samples) == 3
    assert all({"load1", "memory_used_pct", "processes"} <= set(point) for point in samples)
    with pytest.raises(PredictError):
        sample_system(1)
    result = predict_system(samples=5)
    assert result["samples"] == 5
    assert set(result["predicted"]) == {"load1", "memory_used_pct"}
    assert result["reality"]["verdict"] in {"close", "off"}
    assert result["reality"]["mae"] >= 0
