import json
import subprocess
import sys
from pathlib import Path

from omnishield import doctor
from omnishield.cli import main
from omnishield.status import COMPONENTS, status

REPO = Path(__file__).resolve().parents[1]

EXPECTED_CHECKS = {
    "crypto",
    "p1-airgap",
    "p2-identity",
    "p3-tunnel",
    "p4-allowlist",
    "organism",
    "memory",
    "audit",
    "features",
    "hardware",
    "evolution",
    "changeset",
    "reasoning",
    "planning",
    "robustness",
    "learning",
    "ethics",
    "render",
    "answer",
    "language",
    "stream",
    "telemetry",
    "speech",
    "pathtrace",
    "sovereign",
    "mlp",
    "neuron",
    "swarm",
    "ed25519",
    "rdata",
    "skills",
    "corpus",
    "think",
    "chat",
    "omnilang",
    "net",
    "selfstudy",
    "denoise",
    "three_d",
    "simulate",
    "imagery",
    "worship",
    "notify",
    "thermal",
    "signal",
    "documents",
    "predict",
    "knowledge",
    "affect",
    "self_model",
    "existential",
    "swahili",
    "inspect",
    "stealth",
    "federation",
    "vision",
    "actions",
    "interface",
    "synthesis",
    "hypothetical",
    "honesty",
    "payments",
}


def test_every_component_points_at_live_code():
    report = status()
    assert report["product"] == "OmniShield"
    assert len(report["components"]) == len(COMPONENTS) >= 10
    assert report["components_ok"] is True
    assert [item["detail"] for item in report["components"] if not item["ok"]] == []
    assert report["features"]["ok"] is True
    assert report["ok"] is True


def test_status_cli_reports_ok():
    result = subprocess.run(
        [sys.executable, "-m", "omnishield", "status", "--json"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["features"]["built"] > 0


def test_doctor_covers_every_layer():
    report = doctor.run()
    names = {check["check"] for check in report["checks"]}
    assert EXPECTED_CHECKS <= names
    assert report["ok"] is True, [c for c in report["checks"] if not c["ok"]]


def test_doctor_cli_exits_zero_when_every_layer_passes():
    assert main(["doctor"]) == 0


def test_doctor_fails_loudly_when_a_layer_breaks(monkeypatch):
    def broken() -> str:
        raise RuntimeError("deliberate failure")

    monkeypatch.setattr(doctor, "_crypto", broken)
    report = doctor.run()
    assert report["ok"] is False
    failed = [check for check in report["checks"] if not check["ok"]]
    assert [check["check"] for check in failed] == ["crypto"]
    assert "deliberate failure" in failed[0]["detail"]
    assert main(["doctor"]) == 1
