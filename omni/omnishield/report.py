"""One machine-readable document describing the whole system.

`build_report()` merges the ledger audit, the component status and a real doctor
run into a single JSON document with a stable schema version, so CI jobs and
other agents do not have to parse human text.
"""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .doctor import run as doctor_run
from .features import audit as feature_audit
from .status import status as status_report

SCHEMA_VERSION = "1.0.0"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "report.schema.json"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(*, with_doctor: bool = True, generated_at: str | None = None) -> dict[str, Any]:
    features = feature_audit()
    status = status_report()
    doctor = doctor_run() if with_doctor else None

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or _now(),
        "ok": bool(features["ok"] and status["ok"] and (doctor is None or doctor["ok"])),
        "features": {
            "total": features["total"],
            "built": features["built"],
            "coverage_pct": round(features["coverage"] * 100, 1),
            "counts": dict(sorted(features["counts"].items())),
            "problems": list(features["problems"]),
            "ok": bool(features["ok"]),
        },
        "status": {
            "ok": bool(status["ok"]),
            "organism_binary": status["organism_binary"],
            "components": [
                {
                    "id": component["id"],
                    "name": component["name"],
                    "ok": bool(component["ok"]),
                    "detail": component["detail"],
                }
                for component in status["components"]
            ],
            "features": {
                "total": status["features"]["total"],
                "built": status["features"]["built"],
                "coverage_pct": status["features"]["coverage"],
            },
        },
        "doctor": None
        if doctor is None
        else {
            "ok": bool(doctor["ok"]),
            "duration_ms": doctor["duration_ms"],
            "checks": [
                {
                    "check": check["check"],
                    "ok": bool(check["ok"]),
                    "ms": check["ms"],
                    "detail": check["detail"],
                }
                for check in doctor["checks"]
            ],
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.system().lower(),
            "machine": platform.machine().lower(),
        },
    }
    return document


def report_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
