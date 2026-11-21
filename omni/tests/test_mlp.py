import pytest

from omnishield.mlp import Mlp, MlpError, demo, train


def test_forward_shapes_and_errors():
    network = Mlp(hidden=3)
    state = network.forward([0.0, 1.0])
    assert len(state["hidden"]) == 3
    assert 0.0 < state["output"] < 1.0
    assert network.parameters == 3 * 2 + 3 + 3 + 1
    with pytest.raises(MlpError):
        network.forward([1.0])
    with pytest.raises(MlpError):
        network.train_step([1.0, 0.0], 2.0)
    with pytest.raises(MlpError):
        network.train_step([1.0, 0.0], 1.0, rate=0.0)
    with pytest.raises(MlpError):
        Mlp(hidden=0)
    with pytest.raises(MlpError):
        train(epochs=0)


def test_backprop_matches_numerical_gradient():
    network = Mlp(hidden=2, seed=9)
    inputs, target = [0.3, -0.7], 0.8
    epsilon = 1e-6
    original = network.w1[0][0]
    network.w1[0][0] = original + epsilon
    high = network.forward(inputs)["output"]
    network.w1[0][0] = original - epsilon
    low = network.forward(inputs)["output"]
    numeric = 0.5 * ((high - target) ** 2 - (low - target) ** 2) / (2 * epsilon)
    network.w1[0][0] = original
    state = network.forward(inputs)
    hidden, output = state["hidden"], state["output"]
    delta2 = (output - target) * output * (1 - output)
    delta1 = delta2 * network.w2[0][0] * hidden[0] * (1 - hidden[0])
    analytic = delta1 * inputs[0]
    assert abs(numeric - analytic) < 1e-4


def test_learns_xor_and_r_agrees():
    result = demo(epochs=2500)
    assert result["accuracy_before"] <= 0.75
    assert result["accuracy_after"] == 1.0
    assert result["loss_last"] < result["loss_first"]
    assert result["predictions"]["[0.0, 1.0]"] == 1
    assert result["predictions"]["[0.0, 0.0]"] == 0
    if result["r"] is not None:
        assert "mlp converged" in result["r"]["stdout"]
