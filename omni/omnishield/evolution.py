"""Gated self-modification: propose, test in a copy, require human approval, apply, roll back.

The agent may write a patch to its own code. It may not deploy it. Deployment
requires an independent test run against a throwaway copy and a signature from an
approver key that the proposer does not hold. Every step is recorded, and the
previous file is kept so the change is reversible.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, PublicIdentity, SigError, now_ms

DOMAIN = "omnishield.evolution"
APPROVAL_DOMAIN = "omnishield.evolution.approval"
PROTO = ("evolution", 1)
APPROVAL_PROTO = ("evolution-approval", 1)
KINDS = (
    "code_generation",
    "code_review",
    "refactor",
    "bug_fix",
    "feature",
    "performance",
)
IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", "*.pyc", "target", ".venv", "node_modules", ".pytest_cache"
)


class EvolutionError(Exception):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _contained(root: Path, relative: str) -> Path:
    root = root.resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise EvolutionError(f"{relative!r} escapes the project root")
    if not target.is_file():
        raise EvolutionError(f"{relative!r} is not an existing file")
    return target


def _atomic_write(path: Path, data: bytes) -> None:
    descriptor, tmp = tempfile.mkstemp(dir=path.parent, prefix=".evo-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def propose(
    root: str | os.PathLike[str],
    relative: str,
    new_content: str,
    *,
    kind: str,
    rationale: str,
    signer: HybridSigner,
    tests: Iterable[Iterable[str]] = (),
    benchmark: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if kind not in KINDS:
        raise EvolutionError(f"unknown change kind {kind!r}; expected one of {KINDS}")
    if not rationale.strip():
        raise EvolutionError("a proposal needs a rationale")
    target = _contained(Path(root), relative)
    before = target.read_bytes()
    after = new_content.encode("utf-8")
    if before == after:
        raise EvolutionError("the patch does not change the file")
    diff = "".join(
        difflib.unified_diff(
            before.decode("utf-8", "replace").splitlines(True),
            after.decode("utf-8", "replace").splitlines(True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        )
    )
    payload = {
        "kind": kind,
        "path": relative,
        "before_sha256": _sha(before),
        "after_sha256": _sha(after),
        "diff": diff,
        "rationale": rationale,
        "tests": [list(command) for command in tests],
        "benchmark": benchmark,
        "new_content": new_content,
    }
    issued = now_ms() if now is None else int(now)
    envelope = signer.sign(
        canonical_bytes(payload),
        domain=DOMAIN,
        proto_id=PROTO[0],
        proto_version=PROTO[1],
        issued_at_ms=issued,
    )
    return {"proposal": payload, "envelope": envelope}


def verify_proposal(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    payload = dict(document["proposal"])
    verifier.verify(
        document["envelope"],
        canonical_bytes(payload),
        expected_domain=DOMAIN,
        expected_proto=PROTO,
        now=now,
    )
    target = _contained(Path(root), payload["path"])
    if _sha(target.read_bytes()) != payload["before_sha256"]:
        raise EvolutionError("the file changed after this proposal was written")
    if _sha(payload["new_content"].encode("utf-8")) != payload["after_sha256"]:
        raise EvolutionError("proposal content does not match its digest")
    return payload


def review(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    *,
    timeout: float = 120.0,
    now: int | None = None,
) -> dict[str, Any]:
    payload = verify_proposal(document, verifier, root, now=now)
    source = Path(root).resolve()
    with tempfile.TemporaryDirectory(prefix="omnishield-review-") as raw:
        work = Path(raw) / "work"
        shutil.copytree(source, work, ignore=IGNORE)
        (work / payload["path"]).write_text(payload["new_content"], encoding="utf-8")
        runs = []
        for command in payload["tests"]:
            try:
                completed = subprocess.run(
                    command,
                    cwd=work,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                runs.append(
                    {
                        "command": command,
                        "returncode": completed.returncode,
                        "tail": (completed.stdout + completed.stderr)[-600:],
                    }
                )
            except subprocess.TimeoutExpired:
                runs.append({"command": command, "returncode": None, "tail": "timed out"})
        ok = bool(runs) and all(run["returncode"] == 0 for run in runs)
    return {
        "ok": ok,
        "proposal_sha256": _sha(canonical_bytes(payload)),
        "tests": runs,
        "note": "no tests were declared" if not runs else "all declared tests ran",
    }


def approve(
    report: dict[str, Any],
    approver: HybridSigner,
    *,
    approver_name: str,
    now: int | None = None,
) -> dict[str, Any]:
    if not report.get("ok"):
        raise EvolutionError("refusing to approve a proposal whose review failed")
    if not approver_name.strip():
        raise EvolutionError("an approval must name the human or service that granted it")
    issued = now_ms() if now is None else int(now)
    payload = {
        "proposal_sha256": report["proposal_sha256"],
        "review_ok": True,
        "approver": approver_name,
        "approved_at_ms": issued,
    }
    envelope = approver.sign(
        canonical_bytes(payload),
        domain=APPROVAL_DOMAIN,
        proto_id=APPROVAL_PROTO[0],
        proto_version=APPROVAL_PROTO[1],
        issued_at_ms=issued,
    )
    return {"approval": payload, "envelope": envelope}


def apply(
    document: dict[str, Any],
    approval: dict[str, Any],
    verifier: HybridVerifier,
    approver_public: PublicIdentity,
    root: str | os.PathLike[str],
    *,
    backup_dir: str | os.PathLike[str],
    audit: AuditLog | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    payload = verify_proposal(document, verifier, root, now=now)
    approval_payload = dict(approval["approval"])
    try:
        HybridVerifier(approver_public).verify(
            approval["envelope"],
            canonical_bytes(approval_payload),
            expected_domain=APPROVAL_DOMAIN,
            expected_proto=APPROVAL_PROTO,
            now=now,
        )
    except SigError as exc:
        raise EvolutionError(f"approval is not valid: {exc}") from exc
    if approval_payload["proposal_sha256"] != _sha(canonical_bytes(payload)):
        raise EvolutionError("the approval belongs to a different proposal")
    if not approval_payload.get("review_ok"):
        raise EvolutionError("the approval does not confirm a passing review")
    if verifier.identity.key_id == approver_public.key_id:
        raise EvolutionError("the proposer may not approve its own patch")

    target = _contained(Path(root), payload["path"])
    backups = Path(backup_dir)
    backups.mkdir(parents=True, exist_ok=True)
    backup = backups / f"{payload['path'].replace('/', '__')}.{payload['before_sha256'][:12]}.bak"
    backup.write_bytes(target.read_bytes())
    os.chmod(backup, 0o600)
    _atomic_write(target, payload["new_content"].encode("utf-8"))
    record = {
        "applied": payload["path"],
        "kind": payload["kind"],
        "before_sha256": payload["before_sha256"],
        "after_sha256": payload["after_sha256"],
        "approver": approval_payload["approver"],
        "backup": str(backup),
    }
    if audit is not None:
        audit.append("evolution.apply", record)
    return record


def rollback(
    backup: str | os.PathLike[str],
    root: str | os.PathLike[str],
    relative: str,
    *,
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    source = Path(backup)
    if not source.is_file():
        raise EvolutionError(f"backup not found: {source}")
    target = _contained(Path(root), relative)
    data = source.read_bytes()
    _atomic_write(target, data)
    record = {"restored": relative, "sha256": _sha(data)}
    if audit is not None:
        audit.append("evolution.rollback", record)
    return record


def evolve(
    root: str | os.PathLike[str],
    relative: str,
    new_content: str,
    *,
    kind: str,
    rationale: str,
    proposer: HybridSigner,
    approver: HybridSigner,
    approver_name: str,
    tests: Iterable[Iterable[str]],
    backup_dir: str | os.PathLike[str],
    audit: AuditLog | None = None,
    approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The full gate. Without an approval document the change is never written."""
    document = propose(
        root,
        relative,
        new_content,
        kind=kind,
        rationale=rationale,
        signer=proposer,
        tests=tests,
    )
    report = review(document, HybridVerifier(proposer.public_identity), root)
    if not report["ok"]:
        raise EvolutionError("the patched copy failed its declared tests")
    if approval is None:
        raise EvolutionError(
            "review finished but no approval was supplied; the patch was not applied"
        )
    if dict(approval.get("approval", {})).get("proposal_sha256") != report["proposal_sha256"]:
        raise EvolutionError("the approval does not cover the reviewed proposal")
    return apply(
        document,
        approval,
        HybridVerifier(proposer.public_identity),
        approver.public_identity,
        root,
        backup_dir=backup_dir,
        audit=audit,
    )


def generate_code(root, relative, new_content, *, rationale, signer, tests=(), now=None):
    return propose(
        root, relative, new_content, kind="code_generation", rationale=rationale,
        signer=signer, tests=tests, now=now,
    )


def review_code(document, verifier, root, *, timeout=120.0, now=None):
    return review(document, verifier, root, timeout=timeout, now=now)


def refactor(root, relative, new_content, *, rationale, signer, tests=(), now=None):
    return propose(
        root, relative, new_content, kind="refactor", rationale=rationale,
        signer=signer, tests=tests, now=now,
    )


def fix_bug(root, relative, new_content, *, rationale, signer, tests=(), now=None):
    return propose(
        root, relative, new_content, kind="bug_fix", rationale=rationale,
        signer=signer, tests=tests, now=now,
    )


def add_feature(root, relative, new_content, *, rationale, signer, tests=(), now=None):
    return propose(
        root, relative, new_content, kind="feature", rationale=rationale,
        signer=signer, tests=tests, now=now,
    )


def tune_performance(root, relative, new_content, *, rationale, signer, tests=(), benchmark=None, now=None):
    return propose(
        root, relative, new_content, kind="performance", rationale=rationale,
        signer=signer, tests=tests, benchmark=benchmark, now=now,
    )
