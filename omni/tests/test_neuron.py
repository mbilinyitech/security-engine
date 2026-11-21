
import pytest

from omnishield.neuron import (
    NeuronError,
    bench,
    demo,
    dot,
    forward,
    sigmoid,
    train_step,
)


def test_dot_and_sigmoid():
    assert dot([10.0, 20.0, 30.0], [0.5, -1.0, 2.0]) == 45.0
    assert dot([1.0], [0.0]) == 0.0
    assert sigmoid(0.0) == 0.5
    assert 0.0 < sigmoid(-50.0) < 0.001
    assert sigmoid(50.0) >= 0.999
    with pytest.raises(NeuronError):
        dot([1.0, 2.0], [1.0])
    with pytest.raises(NeuronError):
        dot([], [])


def test_forward_and_training_move_towards_the_target():
    inputs = [1.0, -2.0, 0.5]
    weights = [0.1, -0.2, 0.3]
    bias = 0.0
    before = forward(inputs, weights, bias)
    result = train_step(inputs, weights, bias, 1.0, 0.5)
    after = forward(inputs, result["weights"], result["bias"])
    assert after > before
    assert result["loss"] > 0
    with pytest.raises(NeuronError):
        train_step(inputs, weights, bias, 2.0, 0.5)
    with pytest.raises(NeuronError):
        train_step(inputs, weights, bias, 0.5, 0.0)
    with pytest.raises(NeuronError):
        bench(0, 1)


def test_matches_rust_and_r():
    result = demo(dimension=2000, repeats=2)
    assert result["dot"]["matches"] is True
    assert result["forward"]["difference"] < 1e-9
    assert result["training"]["after"] > result["training"]["before"]
    assert result["speed"]["rust_ms_per_dot"] > 0
    if result["r"] is not None:
        assert "all three agree" in result["r"]["stdout"]
