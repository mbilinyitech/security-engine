"""Export live OmniShield state as tidy CSV so R (or any spreadsheet) can analyse it.

Nothing here invents data: features come from the ledger, components from the
status checks, timings from a real doctor run, and the optional tables come from
the real memory database, audit log and payment ledger you point at.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .doctor import run as doctor_run
from .features import load as load_features
from .hybrid import now_ms
from .status import status as status_report


def _write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})
            count += 1
    os.chmod(path, 0o600)
    return count


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export_features(path: Path) -> int:
    rows = [
        {
            "id": feature.id,
            "group": feature.group,
            "status": feature.status,
            "name": feature.name,
            "evidence": feature.evidence,
            "reason": feature.reason,
        }
        for feature in load_features()
    ]
    return _write_csv(
        path, rows, ["id", "group", "status", "name", "evidence", "reason"]
    )


def export_components(path: Path) -> int:
    rows = [
        {
            "id": component["id"],
            "name": component["name"],
            "layer": component["layer"],
            "ok": str(component["ok"]).lower(),
            "evidence": component["evidence"],
            "summary": component["summary"],
        }
        for component in status_report()["components"]
    ]
    return _write_csv(
        path, rows, ["id", "name", "layer", "ok", "evidence", "summary"]
    )


def export_doctor(path: Path) -> int:
    rows = [
        {
            "check": check["check"],
            "ok": str(check["ok"]).lower(),
            "ms": check["ms"],
            "detail": check["detail"],
        }
        for check in doctor_run()["checks"]
    ]
    return _write_csv(path, rows, ["check", "ok", "ms", "detail"])


def export_audit(path: Path, log_path: str | os.PathLike[str]) -> int:
    source = Path(log_path)
    if not source.is_file():
        raise FileNotFoundError(f"audit log not found: {source}")
    rows = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        rows.append(
            {
                "index": entry.get("index", ""),
                "at_ms": entry.get("at_ms", ""),
                "kind": entry.get("kind", ""),
                "payload": json.dumps(entry.get("payload", {}), sort_keys=True),
                "hash": entry.get("hash", ""),
            }
        )
    return _write_csv(path, rows, ["index", "at_ms", "kind", "payload", "hash"])


def export_memory(path: Path, db_path: str | os.PathLike[str]) -> int:
    source = Path(db_path)
    if not source.is_file():
        raise FileNotFoundError(f"memory database not found: {source}")
    document = json.loads(source.read_text(encoding="utf-8"))
    rows = []
    for item in document.get("items", []):
        embedding = [float(value) for value in item.get("embedding", [])]
        norm = math.sqrt(sum(value * value for value in embedding))
        rows.append(
            {
                "id": item.get("id", ""),
                "created_ms": item.get("created_ms", ""),
                "last_access_ms": item.get("last_access_ms", ""),
                "access_count": item.get("access_count", 0),
                "salience": item.get("salience", ""),
                "emotion": item.get("emotion", ""),
                "suppressed": str(item.get("suppressed", False)).lower(),
                "tombstone": str(item.get("tombstone", False)).lower(),
                "content_chars": len(str(item.get("content", ""))),
                "embedding_dim": len(embedding),
                "embedding_norm": round(norm, 6),
            }
        )
    return _write_csv(
        path,
        rows,
        [
            "id",
            "created_ms",
            "last_access_ms",
            "access_count",
            "salience",
            "emotion",
            "suppressed",
            "tombstone",
            "content_chars",
            "embedding_dim",
            "embedding_norm",
        ],
    )


def export_prediction(path: Path) -> int:
    from .predict import linear_forecast, sample_system

    observations = sample_system(6, interval_s=0.01)
    rows = []
    for series in ("load1", "memory_used_pct"):
        values = [point[series] for point in observations]
        model = linear_forecast(values[:-1], horizon=1)
        rows.append(
            {
                "series": series,
                "kind": "nowcast",
                "predicted": model["forecast"][0],
                "observed": values[-1],
                "error": round(values[-1] - model["forecast"][0], 6),
                "slope": model["slope"],
                "r2": model["r2"],
            }
        )
        future = linear_forecast(values, horizon=2)
        for step, predicted in enumerate(future["forecast"], start=1):
            rows.append(
                {
                    "series": series,
                    "kind": f"forecast+{step}",
                    "predicted": predicted,
                    "observed": "",
                    "error": "",
                    "slope": future["slope"],
                    "r2": future["r2"],
                }
            )
    return _write_csv(path, rows, ["series", "kind", "predicted", "observed", "error", "slope", "r2"])


def export_image_quality(path: Path) -> int:
    from .render import quality_metrics, scene

    rendered = scene(160, 100, samples=1, engine="python")
    metrics = quality_metrics(rendered["canvas"])
    rows = [
        {"metric": key, "value": value}
        for key, value in metrics.items()
    ] + [
        {"metric": "engine", "value": rendered["engine"]},
        {"metric": "elapsed_ms", "value": rendered["elapsed_ms"]},
        {"metric": "pixels_per_second", "value": rendered["pixels_per_second"]},
    ]
    return _write_csv(path, rows, ["metric", "value"])


def export_layers(path: Path) -> int:
    layers: dict[str, dict[str, Any]] = {}
    for component in status_report()["components"]:
        record = layers.setdefault(
            component["layer"], {"layer": component["layer"], "components": 0, "ok": 0}
        )
        record["components"] += 1
        record["ok"] += 1 if component["ok"] else 0
    rows = sorted(layers.values(), key=lambda row: (-row["components"], row["layer"]))
    return _write_csv(path, rows, ["layer", "components", "ok"])


def export_stealth(path: Path) -> int:
    from .stealth import StealthChannel, jitter_ms

    channel = StealthChannel(key=b"omnishield-analysis-key-00000000", seed=7)
    rows = []
    index = 0
    for message in range(3):
        wire = channel.seal(f"message {message}".encode(), cover=2)
        for position, cell in enumerate(wire):
            rows.append(
                {
                    "index": index,
                    "message": message,
                    "kind": "data" if position == 0 else "cover",
                    "wire_bytes": len(cell),
                    "jitter_ms": jitter_ms(7, index),
                }
            )
            index += 1
    return _write_csv(path, rows, ["index", "message", "kind", "wire_bytes", "jitter_ms"])


def export_payments(path: Path, ledger_path: str | os.PathLike[str]) -> int:
    source = Path(ledger_path)
    if not source.is_file():
        raise FileNotFoundError(f"payment ledger not found: {source}")
    rows = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        rows.append(
            {
                "intent_id": record.get("intent_id", ""),
                "currency": record.get("currency", ""),
                "amount_cents": record.get("amount_cents", ""),
                "payee": record.get("debit", {}).get("account", ""),
                "approved_by": record.get("approved_by", ""),
                "settled_ms": record.get("settled_ms", ""),
                "receipt": record.get("receipt", ""),
            }
        )
    return _write_csv(
        path,
        rows,
        ["intent_id", "currency", "amount_cents", "payee", "approved_by", "settled_ms", "receipt"],
    )


def export_all(
    directory: str | os.PathLike[str],
    *,
    memory_db: str | os.PathLike[str] | None = None,
    payments_ledger: str | os.PathLike[str] | None = None,
    audit_log: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict[str, Any]] = {}

    def record(name: str, rows: int) -> None:
        target = out / name
        files[name] = {"rows": rows, "sha256": _digest(target)}

    record("features.csv", export_features(out / "features.csv"))
    record("components.csv", export_components(out / "components.csv"))
    record("doctor.csv", export_doctor(out / "doctor.csv"))
    record("stealth.csv", export_stealth(out / "stealth.csv"))
    record("prediction.csv", export_prediction(out / "prediction.csv"))
    record("layers.csv", export_layers(out / "layers.csv"))
    record("image_quality.csv", export_image_quality(out / "image_quality.csv"))
    if audit_log is not None:
        record("audit.csv", export_audit(out / "audit.csv", audit_log))
    if memory_db is not None:
        record("memory.csv", export_memory(out / "memory.csv", memory_db))
    if payments_ledger is not None:
        record("payments.csv", export_payments(out / "payments.csv", payments_ledger))

    manifest_rows = [
        {"file": name, "rows": info["rows"], "sha256": info["sha256"]}
        for name, info in files.items()
    ]
    _write_csv(out / "manifest.csv", manifest_rows, ["file", "rows", "sha256"])

    manifest = {
        "product": "OmniShield",
        "generated_at_ms": now_ms(),
        "files": files,
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    return manifest
