import sys

import pytest

from omnishield.audit import AuditLog
from omnishield.evolution import (
    KINDS,
    EvolutionError,
    apply,
    approve,
    propose,
    review,
    rollback,
)
from omnishield.hybrid import HybridSigner, HybridVerifier

FIXED = "def add(a, b):\n    return a + b\n"
BROKEN = "def add(a, b):\n    return a * b\n"
ORIGINAL = "def add(a, b):\n    return a - b\n"


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "calc.py").write_text(ORIGINAL, encoding="utf-8")
    (root / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return root


def _proposal(project, content, kind="bug_fix"):
    signer = HybridSigner.generate()
    document = propose(
        project,
        "calc.py",
        content,
        kind=kind,
        rationale="fix the operator",
        signer=signer,
        tests=[[sys.executable, "-m", "pytest", "-q"]],
    )
    return signer, document


def test_proposal_carries_a_real_diff(project):
    _, document = _proposal(project, FIXED)
    assert "-    return a - b" in document["proposal"]["diff"]
    assert "+    return a + b" in document["proposal"]["diff"]


def test_review_runs_the_tests_and_passes(project):
    signer, document = _proposal(project, FIXED)
    report = review(document, HybridVerifier(signer.public_identity), project)
    assert report["ok"] is True
    assert report["tests"][0]["returncode"] == 0


def test_review_fails_when_the_patch_breaks_tests(project):
    signer, document = _proposal(project, BROKEN)
    report = review(document, HybridVerifier(signer.public_identity), project)
    assert report["ok"] is False


def test_review_refuses_a_stale_proposal(project):
    signer, document = _proposal(project, FIXED)
    (project / "calc.py").write_text("def add(a, b):\n    return 0\n", encoding="utf-8")
    with pytest.raises(EvolutionError, match="changed"):
        review(document, HybridVerifier(signer.public_identity), project)


def test_apply_requires_an_approval(project):
    signer, document = _proposal(project, FIXED)
    report = review(document, HybridVerifier(signer.public_identity), project)
    approver = HybridSigner.generate()
    with pytest.raises(EvolutionError):
        apply(
            document,
            {"approval": {}, "envelope": {}},
            HybridVerifier(signer.public_identity),
            approver.public_identity,
            project,
            backup_dir=project.parent / "backups",
        )
    assert (project / "calc.py").read_text(encoding="utf-8") == ORIGINAL
    assert report["ok"] is True


def test_apply_then_rollback_restores_the_file(project, tmp_path):
    signer, document = _proposal(project, FIXED)
    report = review(document, HybridVerifier(signer.public_identity), project)
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
    assert (project / "calc.py").read_text(encoding="utf-8") == FIXED
    assert record["approver"] == "human:amina"
    assert audit.verify() == 1
    rollback(record["backup"], project, "calc.py", audit=audit)
    assert (project / "calc.py").read_text(encoding="utf-8") == ORIGINAL
    assert audit.verify() == 2


def test_the_proposer_cannot_approve_its_own_patch(project, tmp_path):
    signer, document = _proposal(project, FIXED)
    report = review(document, HybridVerifier(signer.public_identity), project)
    approval = approve(report, signer, approver_name="me")
    with pytest.raises(EvolutionError, match="may not approve"):
        apply(
            document,
            approval,
            HybridVerifier(signer.public_identity),
            signer.public_identity,
            project,
            backup_dir=tmp_path / "backups",
        )


def test_failed_review_cannot_be_approved(project):
    signer, document = _proposal(project, BROKEN)
    report = review(document, HybridVerifier(signer.public_identity), project)
    with pytest.raises(EvolutionError, match="failed"):
        approve(report, HybridSigner.generate(), approver_name="human:bob")


def test_path_escape_and_unknown_kind_are_refused(project):
    signer = HybridSigner.generate()
    with pytest.raises(EvolutionError, match="escapes"):
        propose(project, "../evil.py", FIXED, kind="bug_fix", rationale="x", signer=signer)
    with pytest.raises(EvolutionError, match="unknown change kind"):
        propose(project, "calc.py", FIXED, kind="magic", rationale="x", signer=signer)
    with pytest.raises(EvolutionError, match="does not change"):
        propose(project, "calc.py", ORIGINAL, kind="refactor", rationale="x", signer=signer)


@pytest.mark.parametrize("kind", KINDS)
def test_every_change_kind_can_be_proposed(project, kind):
    signer = HybridSigner.generate()
    document = propose(project, "calc.py", FIXED, kind=kind, rationale="x", signer=signer)
    assert document["proposal"]["kind"] == kind
