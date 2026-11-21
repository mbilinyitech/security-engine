import json

import pytest

from omnishield.swarm import (
    HEADER,
    Shard,
    SwarmError,
    SwarmNode,
    accuracy,
    demo,
    guard,
    json_bytes,
    make_data,
    pack_tensor,
    train_step,
    unpack,
)


def test_tensor_frames_are_compact_and_round_trip():
    vector = [round(0.123456 + index * 0.017, 6) for index in range(128)]
    frame = pack_tensor(vector)
    assert len(frame) == HEADER.size + 4 * len(vector)
    assert len(frame) < json_bytes(vector)
    message = unpack(frame)
    assert message["kind"] == "tensor"
    assert message["vector"] == pytest.approx(vector, abs=1e-6)
    with pytest.raises(SwarmError):
        unpack(b"XXXX" + frame[4:])
    with pytest.raises(SwarmError):
        pack_tensor([], kind=9)


def test_two_nodes_match_one_model(tmp_path):
    first = Shard([[0.5, -0.25, 0.1]], [0.05], start=0)
    second = Shard([[-0.2, 0.75, 0.3]], [-0.1], start=1)
    alpha = SwarmNode("alpha", first)
    beta = SwarmNode("beta", second)
    alpha.start()
    port = beta.start()
    try:
        vector = [1.0, 2.0, -1.0]
        local = [a + b for a, b in zip(first.partial(vector), second.partial(vector), strict=True)]
        remote = alpha.infer(vector, [("127.0.0.1", port)])
        assert remote == pytest.approx(local, abs=1e-6)
        assert beta.requests == 1
    finally:
        alpha.stop()
        beta.stop()
    first.save(tmp_path / "shard.json")
    loaded = Shard.load(tmp_path / "shard.json")
    assert loaded.partial([1.0, 2.0, -1.0]) == pytest.approx(first.partial([1.0, 2.0, -1.0]))


def test_online_learning_converges_and_guard_refuses():
    data = make_data(samples=120, width=6)
    train, holdout = data[:60], data[60:]
    first = Shard([[0.0] * 6], [0.0], start=0)
    second = Shard([[0.0] * 6], [0.0], start=1)
    before = accuracy([first, second], holdout)
    losses = [train_step([first, second], vector, label) for vector, label in train]
    after = accuracy([first, second], holdout)
    assert before == pytest.approx(0.5)
    assert after > 0.9
    assert losses[-1] < losses[0]
    assert guard([2.0, 0.1])["accepted"] is True
    assert guard([0.2, 0.15])["accepted"] is False
    assert guard([float("nan"), 1.0])["accepted"] is False


def test_demo_reports_every_number():
    result = demo(samples=80)
    assert result["distributed"]["matches_local"] is True
    assert result["protocol"]["tensor_bytes"] < result["protocol"]["json_bytes"]
    assert result["learning"]["accuracy_after"] > 0.9
    assert result["guard"]["confident"]["accepted"] is True
    json.dumps(result)
