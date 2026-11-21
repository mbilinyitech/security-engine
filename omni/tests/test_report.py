import json
import re
import subprocess
import sys
from pathlib import Path

from omnishield.report import SCHEMA_VERSION, build_report, report_schema

ROOT = Path(__file__).resolve().parents[1]
PYTHON_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "null": type(None),
}


def _matches_type(value, name: str) -> bool:
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, PYTHON_TYPES[name]) and not isinstance(value, bool)


def _errors(instance, schema, path="$"):
    errors = []
    declared = schema.get("type")
    if declared is not None:
        allowed = declared if isinstance(declared, list) else [declared]
        if not any(_matches_type(instance, name) for name in allowed):
            return [f"{path}: expected {allowed}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if (
        isinstance(instance, str)
        and "pattern" in schema
        and not re.search(schema["pattern"], instance)
    ):
        errors.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} below {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} above {schema['maximum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing {key}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                errors += _errors(value, properties[key], f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected {key}")
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            for key, value in instance.items():
                if key not in properties:
                    errors += _errors(value, extra, f"{path}.{key}")
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors += _errors(item, schema["items"], f"{path}[{index}]")
    return errors


def _run(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "omnishield", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_report_has_the_documented_shape():
    document = build_report(with_doctor=False)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["ok"] is True
    assert document["features"]["total"] == 500
    assert sum(document["features"]["counts"].values()) == 500
    assert document["features"]["coverage_pct"] == round(
        document["features"]["built"] / 500 * 100, 1
    )
    assert document["doctor"] is None
    assert isinstance(document["environment"]["python"], str)


def test_report_with_doctor_lists_every_check():
    document = build_report(with_doctor=True)
    checks = document["doctor"]["checks"]
    assert len(checks) == 64
    assert all(check["ok"] for check in checks)
    assert document["doctor"]["duration_ms"] >= 0


def test_report_validates_against_the_published_schema():
    document = build_report(with_doctor=False)
    assert _errors(document, report_schema()) == []


def test_schema_rejects_a_report_missing_a_section():
    document = build_report(with_doctor=False)
    del document["status"]
    assert _errors(document, report_schema())


def test_cli_report_is_json_and_exit_code_follows_ok():
    completed = _run("report", "--no-doctor")
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["ok"] is True


def test_cli_report_can_print_the_schema():
    completed = _run("report", "--schema")
    assert completed.returncode == 0
    schema = json.loads(completed.stdout)
    assert schema["$schema"].startswith("https://json-schema.org/")
    assert "schema_version" in schema["properties"]


def test_cli_report_writes_the_document_to_a_file(tmp_path):
    target = tmp_path / "report.json"
    completed = _run("report", "--no-doctor", "--out", str(target))
    assert completed.returncode == 0
    assert json.loads(target.read_text(encoding="utf-8"))["ok"] is True


def test_features_list_json_is_machine_readable():
    completed = _run("features", "list", "--json", "--status", "implemented")
    assert completed.returncode == 0
    items = json.loads(completed.stdout)
    assert len(items) == 230
    assert all({"id", "status", "evidence", "name"} <= set(item) for item in items)
    assert all(item["status"] == "implemented" for item in items)


def test_status_and_doctor_and_audit_json_agree():
    status = json.loads(_run("status", "--json").stdout)
    audit = json.loads(_run("features", "audit", "--json").stdout)
    report = json.loads(_run("report", "--no-doctor").stdout)
    assert status["features"]["built"] == audit["built"] == report["features"]["built"]
    assert len(status["components"]) == len(report["status"]["components"])
