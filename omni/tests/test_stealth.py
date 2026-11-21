import json
import subprocess
import sys
from itertools import pairwise

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from omnishield.stealth import (
    DEFAULT_CELL,
    StealthChannel,
    StealthError,
    batch,
    cover_cell,
    digest,
    frame_cell,
    jitter_ms,
    metrics,
    onion_peel,
    onion_route,
    probe_schedule,
    unframe_cell,
)


def test_framing_matches_the_rust_vectors():
    assert frame_cell(b"hi", cell=16, seed=7).hex() == "0000000268698b5e0c29b0abdb1c34a3"
    assert cover_cell(cell=16, seed=7).hex() == "ffffffff8b5e0c29b0abdb1c34a39b1a"
    assert jitter_ms(3, 0) == 244
    assert jitter_ms(3, 1) == 255


def test_framing_round_trip_and_limits():
    cell = frame_cell(b"the quick brown fox", seed=42)
    assert len(cell) == DEFAULT_CELL
    assert unframe_cell(cell) == b"the quick brown fox"
    assert unframe_cell(cover_cell(seed=9)) is None
    with pytest.raises(StealthError):
        frame_cell(b"x" * 600)
    with pytest.raises(StealthError):
        frame_cell(b"x", cell=4)
    with pytest.raises(StealthError):
        unframe_cell(b"\x00\x00\xff\xff" + b"\x00" * 8)
    assert batch([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_channel_seals_cover_and_hides_payloads():
    channel = StealthChannel(key=b"k" * 32, seed=1)
    wire = channel.seal(b"secret order", cover=3)
    assert len(wire) == 4
    assert len({len(cell) for cell in wire}) == 1
    assert channel.open(wire) == [b"secret order"]
    assert metrics(wire)["uniform"] is True
    assert metrics(wire)["entropy_bits_per_byte"] > 7.5
    assert len(digest(wire)) == 64


def test_channel_refuses_tampering_and_wrong_keys():
    channel = StealthChannel(key=b"k" * 32, seed=1)
    wire = channel.seal(b"secret", cover=1)
    tampered = bytearray(wire[0])
    tampered[-1] ^= 0x01
    with pytest.raises(StealthError, match="authentication"):
        channel.open([bytes(tampered)])
    stranger = StealthChannel(key=b"z" * 32, seed=1)
    with pytest.raises(StealthError, match="authentication"):
        stranger.open(wire)


def _hops(count):
    keys = [X25519PrivateKey.generate() for _ in range(count)]
    private = [
        key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        for key in keys
    ]
    public = [
        key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        for key in keys
    ]
    hops = [{"address": f"10.0.0.{index + 2}", "public": public[index]} for index in range(count)]
    return hops, private


def test_onion_reveals_only_the_next_hop():
    hops, private = _hops(3)
    layer = onion_route(hops, b"final payload")
    first = onion_peel(layer, private[0])
    assert first["next"] == "10.0.0.3"
    assert first["final"] is False
    second = onion_peel(json.loads(first["payload"]), private[1])
    assert second["next"] == "10.0.0.4"
    third = onion_peel(json.loads(second["payload"]), private[2])
    assert third["next"] is None
    assert third["final"] is True
    assert third["payload"] == b"final payload"


def test_onion_refuses_the_wrong_key_and_bad_routes():
    hops, private = _hops(2)
    layer = onion_route(hops, b"x")
    with pytest.raises(StealthError, match="not addressed"):
        onion_peel(layer, private[1])
    with pytest.raises(StealthError):
        onion_route([], b"x")
    with pytest.raises(StealthError):
        onion_route([{"address": "a"}], b"x")
    with pytest.raises(StealthError):
        onion_peel({"v": 9}, private[0])


def test_probe_schedule_is_randomised_rate_limited_and_complete():
    targets = [f"10.0.0.{index}" for index in range(8)]
    schedule = probe_schedule(targets, seed=11, base_ms=100, spread_ms=50)
    assert sorted(item["target"] for item in schedule) == sorted(targets)
    assert [item["index"] for item in schedule] == list(range(8))
    delays = [item["at_ms"] for item in schedule]
    assert delays == sorted(delays)
    gaps = [delays[0]] + [b - a for a, b in pairwise(delays)]
    assert all(100 <= gap <= 150 for gap in gaps)
    assert probe_schedule(targets, seed=11, base_ms=100, spread_ms=50) == schedule
    assert [item["target"] for item in probe_schedule(targets, seed=12, base_ms=100, spread_ms=50)] != [
        item["target"] for item in schedule
    ]


def test_doctor_jsonl_emits_one_object_per_check():
    completed = subprocess.run(
        [sys.executable, "-m", "omnishield", "doctor", "--jsonl"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    assert len(lines) == 64
    for line in lines:
        record = json.loads(line)
        assert {"check", "ok", "ms", "detail"} <= set(record)


def test_export_writes_a_uniform_stealth_table(tmp_path):
    from omnishield.export import export_stealth

    path = tmp_path / "stealth.csv"
    rows = export_stealth(path)
    assert rows == 9
    text = path.read_text(encoding="utf-8").splitlines()
    assert text[0] == "index,message,kind,wire_bytes,jitter_ms"
    assert all(line.split(",")[3] == "540" for line in text[1:])
