import sys

import pytest

from omnishield.audit import AuditLog
from omnishield.changeset import (
    ChangesetError,
    apply,
    approve,
    propose,
    review,
    rollback,
)
from omnishield.hybrid import HybridSigner, HybridVerifier

ORIGINAL_CALC = "def add(a, b):\n    return a - b\n"
FIXED_CALC = "def add(a, b):\n    return a + b\n"
ORIGINAL_TEST = "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
EXTENDED_TEST = (
    "from calc import add\nfrom helpers import double\n\n\n"
    "def test_add():\n    assert add(2, 3) == 5\n\n\n"
    "def test_double():\n    assert double(3) == 6\n"
)
HELPERS = "def double(value):\n    return value * 2\n"
PYTEST = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "calc.py").write_text(ORIGINAL_CALC, encoding="utf-8")
    (root / "test_calc.py").write_text(ORIGINAL_TEST, encoding="utf-8")
    (root / "obsolete.py").write_text("OLD = True\n", encoding="utf-8")
    return root


def _edits(calc=FIXED_CALC):
    return [
        {"path": "calc.py", "action": "modify", "content": calc},
        {"path": "helpers.py", "action": "create", "content": HELPERS},
        {"path": "test_calc.py", "action": "modify", "content": EXTENDED_TEST},
    ]


def _document(project, edits=None, tests=(PYTEST,)):
    signer = HybridSigner.generate()
    document = propose(
        project,
        edits if edits is not None else _edits(),
        kind="feature",
        rationale="add a helper and fix the operator",
        signer=signer,
        tests=tests,
    )
    return signer, document


def test_three_files_apply_as_one_unit_then_roll_back(project, tmp_path):
    signer, document = _document(project)
    report = review(document, HybridVerifier(signer.public_identity), project)
    assert report["ok"] is True
    assert report["files"] == 3

    approver = HybridSigner.generate()
    approval = approve(report, approver, approver_name="human:amina")
    audit = AuditLog(tmp_path / "audit.log", key=b"k" * 32)
    record = apply(
        document,
        approval,
        HybridVerifier(signer.public_identity),
        approver.public_identity,
        project,
        backup_dir=tmp_path / "backups",
        audit=audit,
    )
    assert (project / "calc.py").read_text(encoding="utf-8") == FIXED_CALC
    assert (project / "helpers.py").read_text(encoding="utf-8") == HELPERS
    assert (project / "test_calc.py").read_text(encoding="utf-8") == EXTENDED_TEST
    assert record["files"] == ["calc.py", "helpers.py", "test_calc.py"]
    assert audit.verify() == 1

    rollback(record["journal"], project, audit=audit)
    assert (project / "calc.py").read_text(encoding="utf-8") == ORIGINAL_CALC
    assert (project / "test_calc.py").read_text(encoding="utf-8") == ORIGINAL_TEST
    assert not (project / "helpers.py").exists()
    assert audit.verify() == 2


def test_a_failing_health_check_restores_every_file(project, tmp_path):
    signer, document = _document(project)
    report = review(document, HybridVerifier(signer.public_identity), project)
    approver = HybridSigner.generate()
    approval = approve(report, approver, approver_name="human:bob")
    with pytest.raises(ChangesetError, match="health check failed"):
        apply(
            document,
            approval,
            HybridVerifier(signer.public_identity),
            approver.public_identity,
            project,
            backup_dir=tmp_path / "backups",
            health=[sys.executable, "-c", "import sys; sys.exit(3)"],
        )
    assert (project / "calc.py").read_text(encoding="utf-8") == ORIGINAL_CALC
    assert not (project / "helpers.py").exists()
    assert (project / "test_calc.py").read_text(encoding="utf-8") == ORIGINAL_TEST


def test_health_check_passes_and_is_recorded(project, tmp_path):
    signer, document = _document(project)
    report = review(document, HybridVerifier(signer.public_identity), project)
    approver = HybridSigner.generate()
    approval = approve(report, approver, approver_name="human:bob")
    record = apply(
        document,
        approval,
        HybridVerifier(signer.public_identity),
        approver.public_identity,
        project,
        backup_dir=tmp_path / "backups",
        health=PYTEST,
    )
    assert record["health"] == "passed"


def test_drift_in_any_file_blocks_the_review(project):
    signer, document = _document(project)
    (project / "test_calc.py").write_text("def test_nothing():\n    pass\n", encoding="utf-8")
    with pytest.raises(ChangesetError, match="changed"):
        review(document, HybridVerifier(signer.public_identity), project)


def test_a_create_target_must_not_exist(project):
    signer = HybridSigner.generate()
    with pytest.raises(ChangesetError, match="already exists"):
        propose(
            project,
            [{"path": "calc.py", "action": "create", "content": "x = 1\n"}],
            kind="feature",
            rationale="x",
            signer=signer,
        )


def test_delete_is_part_of_the_changeset(project, tmp_path):
    signer = HybridSigner.generate()
    document = propose(
        project,
        [
            {"path": "obsolete.py", "action": "delete"},
            {"path": "calc.py", "action": "modify", "content": FIXED_CALC},
        ],
        kind="refactor",
        rationale="remove dead code",
        signer=signer,
        tests=[PYTEST],
    )
    report = review(document, HybridVerifier(signer.public_identity), project)
    assert report["ok"] is True
    approver = HybridSigner.generate()
    approval = approve(report, approver, approver_name="human:amina")
    record = apply(
        document,
        approval,
        HybridVerifier(signer.public_identity),
        approver.public_identity,
        project,
        backup_dir=tmp_path / "backups",
    )
    assert not (project / "obsolete.py").exists()
    rollback(record["journal"], project)
    assert (project / "obsolete.py").exists()


def test_an_approval_for_another_changeset_is_refused(project, tmp_path):
    signer = HybridSigner.generate()
    first = propose(project, _edits(), kind="feature", rationale="a", signer=signer, tests=[PYTEST])
    second = propose(
        project,
        [{"path": "calc.py", "action": "modify", "content": "def add(a, b):\n    return b + a\n"}],
        kind="refactor",
        rationale="b",
        signer=signer,
        tests=[PYTEST],
    )
    report = review(first, HybridVerifier(signer.public_identity), project)
    approver = HybridSigner.generate()
    approval = approve(report, approver, approver_name="human:amina")
    with pytest.raises(ChangesetError, match="different"):
        apply(
            second,
            approval,
            HybridVerifier(signer.public_identity),
            approver.public_identity,
            project,
            backup_dir=tmp_path / "backups",
        )


def test_the_proposer_cannot_approve(project, tmp_path):
    signer, document = _document(project)
    report = review(document, HybridVerifier(signer.public_identity), project)
    approval = approve(report, signer, approver_name="me")
    with pytest.raises(ChangesetError, match="own changeset"):
        apply(
            document,
            approval,
            HybridVerifier(signer.public_identity),
            signer.public_identity,
            project,
            backup_dir=tmp_path / "backups",
        )


def test_a_failing_review_cannot_be_approved(project):
    signer, document = _document(project, edits=_edits(calc="def add(a, b):\n    return a * b\n"))
    report = review(document, HybridVerifier(signer.public_identity), project)
    assert report["ok"] is False
    with pytest.raises(ChangesetError, match="failed"):
        approve(report, HybridSigner.generate(), approver_name="human:bob")


def test_path_escape_and_duplicate_paths_are_refused(project):
    signer = HybridSigner.generate()
    with pytest.raises(ChangesetError, match="escapes"):
        propose(
            project,
            [{"path": "../evil.py", "action": "create", "content": "x = 1\n"}],
            kind="feature",
            rationale="x",
            signer=signer,
        )
    with pytest.raises(ChangesetError, match="duplicate"):
        propose(
            project,
            [
                {"path": "calc.py", "action": "modify", "content": FIXED_CALC},
                {"path": "calc.py", "action": "delete"},
            ],
            kind="refactor",
            rationale="x",
            signer=signer,
        )
    with pytest.raises(ChangesetError, match="at least one edit"):
        propose(project, [], kind="refactor", rationale="x", signer=signer)
