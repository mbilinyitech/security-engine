import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from omnishield.features import (
    STATUSES,
    audit,
    by_group,
    by_status,
    get,
    load,
    validate,
)

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def catalog():
    return load()


def test_catalog_has_500_sequential_ids(catalog):
    assert len(catalog) == 500
    assert [feature.id for feature in catalog] == list(range(1, 501))


def test_catalog_has_twenty_groups_of_twenty_five(catalog):
    groups = {}
    for feature in catalog:
        groups[feature.group] = groups.get(feature.group, 0) + 1
    assert len(groups) == 20
    assert set(groups.values()) == {25}


def test_every_claim_validates(catalog):
    assert validate(catalog) == []


def test_implemented_entries_carry_evidence_and_reason(catalog):
    implemented = by_status("implemented", catalog)
    assert implemented
    for feature in implemented:
        assert feature.evidence, f"#{feature.id} has no evidence"
        assert feature.reason, f"#{feature.id} has no reason"


def test_evidence_points_at_real_symbols(catalog):
    for feature in by_status("implemented", catalog):
        location = feature.evidence.split("::")[0]
        assert (REPO / location).exists(), f"#{feature.id}: {location} is missing"


def test_statuses_are_known_and_counted(catalog):
    report = audit(catalog)
    assert set(report["counts"]) == set(STATUSES)
    assert sum(report["counts"].values()) == 500
    assert report["ok"] is True


def test_duplicates_point_at_existing_features(catalog):
    ids = {feature.id for feature in catalog}
    for feature in by_status("duplicate", catalog):
        target = int(feature.reason.split("#", 1)[1].split()[0].rstrip("."))
        assert target in ids
        assert target != feature.id


def test_high_risk_features_have_gated_code_and_no_free_pass(catalog):
    high_risk = {72, 177, 199, 200, 243, 465, 466, 467, 468, 469, 470}
    assert not {feature.id for feature in by_status("refused", catalog)} & high_risk
    for identifier in high_risk:
        feature = get(identifier, catalog)
        assert feature.status in {"implemented", "partial"}, identifier
        assert feature.evidence, identifier
        if feature.status == "partial":
            assert feature.reason, identifier


def test_audit_logging_is_claimed_as_implemented(catalog):
    feature = get(400, catalog)
    assert feature.status == "implemented"
    assert "audit.py" in feature.evidence


def test_existential_group_keeps_metaphysics_refused(catalog):
    existential = by_group("Existential", catalog)
    metaphysical = {493, 495, 496, 497, 498, 499, 500}
    for feature in existential:
        if feature.id in metaphysical:
            assert feature.status == "refused", feature.name
        if feature.status == "implemented":
            assert feature.evidence.startswith("omnishield/existential.py::"), feature.name


def test_cli_features_audit_reports_ok():
    result = subprocess.run(
        [sys.executable, "-m", "omnishield.cli", "features", "audit", "--json"],
        cwd=str(REPO),
        env={**os.environ, "OMNISHIELD_HOME": "/tmp/omnishield-features-test"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["total"] == 500


def test_cli_features_list_and_show():
    listed = subprocess.run(
        [sys.executable, "-m", "omnishield.cli", "features", "list", "--status", "implemented"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert listed.returncode == 0
    expected = audit()["counts"]["implemented"]
    assert len(listed.stdout.strip().splitlines()) == expected

    shown = subprocess.run(
        [sys.executable, "-m", "omnishield.cli", "features", "show", "400"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert shown.returncode == 0
    assert json.loads(shown.stdout)["name"] == "Audit Logging"
