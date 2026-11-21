import os
import subprocess
import sys
from pathlib import Path

import pytest

from omnishield.hybrid import SigError
from omnishield.keystore import FileKeyStore
from omnishield.organism import (
    OrganismClient,
    OrganismError,
    binary_path,
    build_binary,
    sign_state,
    verify_state,
)
from omnishield.p2_identity import DeviceIdentity

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def binary():
    found = binary_path()
    if found is None:
        try:
            found = build_binary()
        except OrganismError as exc:
            pytest.skip(f"organism core is not buildable here: {exc}")
    return found


@pytest.fixture()
def client(binary):
    with OrganismClient(binary) as session:
        yield session


def test_discover_lists_methods(client):
    catalog = client.discover()
    names = [method["name"] for method in catalog["methods"]]
    assert "search.astar" in names
    assert "dp.knapsack" in names
    assert "plan.mcts" in names


def test_energy_tick(client):
    report = client.call("energy.tick", {"capacity": 10.0, "cost": 4.0, "recharge": 1.0})
    assert report["level"] == 7.0
    assert report["fraction"] == pytest.approx(0.7)
    assert report["dead"] is False


def test_homeostasis_converges(client):
    result = client.call(
        "homeostasis.step",
        {"target": 2.0, "start": -1.0, "learning_rate": 0.4, "iterations": 80},
    )
    assert abs(result["final"] - 2.0) < 1e-6
    assert result["loss"] < 1e-12


def test_astar_returns_the_shortest_path(client):
    result = client.call(
        "search.astar",
        {
            "nodes": 3,
            "start": 0,
            "goal": 2,
            "edges": [[0, 1, 1.0], [1, 2, 1.0], [0, 2, 5.0]],
        },
    )
    assert result["path"] == [0, 1, 2]
    assert result["cost"] == 2.0


def test_pagerank_totals_one(client):
    result = client.call(
        "graph.pagerank",
        {"nodes": 3, "edges": [[0, 1], [1, 2], [2, 0]], "top_k": 3},
    )
    assert abs(result["total"] - 1.0) < 1e-9
    assert result["top"][0]["score"] > 0.3


def test_mcts_prefers_moving_forward(client):
    result = client.call(
        "plan.mcts",
        {"length": 12, "iterations": 2000, "horizon": 10, "seed": 7},
    )
    assert result["best_action"] == 1


def test_ga_approaches_the_target(client):
    result = client.call(
        "evolve.ga",
        {"target": [0.5, -0.5], "population": 60, "generations": 120, "seed": 5},
    )
    assert result["best_distance"] < 1e-2


def test_knapsack_known_optimum(client):
    result = client.call(
        "dp.knapsack",
        {"weights": [1, 3, 4, 5], "values": [1, 4, 5, 7], "capacity": 7},
    )
    assert result["best_value"] == 9


def test_unknown_method_surfaces_32601(client):
    with pytest.raises(OrganismError, match="-32601"):
        client.call("does.not.exist")


def test_invalid_params_surface_32602(client):
    with pytest.raises(OrganismError, match="-32602"):
        client.call("energy.tick", {"capacity": 10.0})


def test_signed_state_round_trip(client, tmp_path):
    identity = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "org")
    document = sign_state(client, identity.signer)
    payload = verify_state(document, identity.identity)
    assert payload["state"]["alive"] is True
    assert payload["state"]["version"]


def test_tampered_state_is_rejected(client, tmp_path):
    identity = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "org")
    document = sign_state(client, identity.signer)
    document["payload"]["state"]["alive"] = False
    with pytest.raises(SigError):
        verify_state(document, identity.identity)


def test_cli_organism_state_round_trip(tmp_path):
    home = tmp_path / "home"
    env = {**os.environ, "OMNISHIELD_HOME": str(home)}

    def run(*arguments):
        return subprocess.run(
            [sys.executable, "-m", "omnishield.cli", *arguments],
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    assert run("keygen", "--out", str(tmp_path / "pub.json")).returncode == 0
    signed = run("organism", "state", "--sign", "--out", str(tmp_path / "state.json"))
    assert signed.returncode == 0, signed.stderr
    checked = run(
        "organism",
        "verify-state",
        str(tmp_path / "state.json"),
        "--pub",
        str(tmp_path / "pub.json"),
    )
    assert checked.returncode == 0, checked.stderr


def test_memory_session_round_trip(client):
    stats = client.call("memory.init", {"capacity": 8})
    assert stats["capacity"] == 8
    first = client.call(
        "memory.insert",
        {"content": "mkutano", "embedding": [1.0, 0.0], "now_ms": 1000, "salience": 0.9},
    )
    client.call(
        "memory.insert",
        {"content": "barua", "embedding": [0.0, 1.0], "now_ms": 1000, "salience": 0.4},
    )
    found = client.call("memory.search", {"embedding": [1.0, 0.0], "limit": 2, "now_ms": 2000})
    assert found[0]["id"] == first["id"]
    assert client.call("memory.stats")["live"] == 2


def test_memory_consolidation_and_decay(client):
    client.call("memory.init", {"capacity": 8, "decay_per_hour": 1.0, "floor": 0.5})
    client.call("memory.insert", {"content": "a", "embedding": [1.0], "now_ms": 0, "salience": 0.6})
    client.call("memory.insert", {"content": "b", "embedding": [1.0], "now_ms": 0, "salience": 0.6})
    merged = client.call("memory.consolidate", {"threshold": 0.99, "now_ms": 0})
    assert merged["merged"] == 1
    forgotten = client.call("memory.decay", {"now_ms": 10_000_000})
    assert forgotten["forgotten"] == 1


def test_control_signals_and_step(client):
    homes = [
        {"name": "energy", "target": 0.8, "current": 0.2, "tolerance": 0.2, "weight": 2.0}
    ]
    signals = client.call("control.signals", {"homes": homes})
    assert signals["dominant"]["name"] == "energy"
    assert signals["signals"][0]["urgency"] == 1.0
    stepped = client.call(
        "control.step",
        {"homes": homes, "name": "energy", "gain": 1.0, "max_step": 0.3},
    )
    assert stepped["value"] == pytest.approx(0.5)


def test_belief_update_and_decision(client):
    belief = client.call(
        "belief.update",
        {"alpha": 1, "beta": 1, "success_count": 3, "failure_count": 1},
    )
    assert belief["mean"] == pytest.approx(4.0 / 6.0)
    assert belief["log_likelihood"] < 0.0

    decision = client.call(
        "belief.decide",
        {
            "alpha": 8,
            "beta": 2,
            "actions": [
                {"name": "safe", "utility_success": 1.0, "utility_failure": 1.0},
                {"name": "risky", "utility_success": 10.0, "utility_failure": -100.0},
            ],
        },
    )
    assert decision["best"] == "safe"


def test_bandit_explores_unvisited_arms(client):
    client.call("bandit.init", {"arms": ["a", "b"]})
    first = client.call("bandit.select")
    client.call("bandit.update", {"index": first["index"], "reward": 1.0})
    second = client.call("bandit.select")
    assert second["index"] != first["index"]
