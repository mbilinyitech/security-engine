"""Transactional self-modification: many files, one signed changeset, all or nothing.

`evolution.py` patches one file. This is the second system: a changeset groups
creates, edits and deletes across several files, is reviewed as a unit in a
throwaway copy, needs an approval key the proposer does not hold, and is applied
through a journal. If any write fails, or a health command fails afterwards,
every file is restored and the changeset is reported as rolled back.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .canonical import canonical_bytes
from .evolution import IGNORE, KINDS
from .hybrid import HybridSigner, HybridVerifier, PublicIdentity, SigError, now_ms

DOMAIN = "omnishield.changeset"
APPROVAL_DOMAIN = "omnishield.changeset.approval"
PROTO = ("changeset", 1)
APPROVAL_PROTO = ("changeset-approval", 1)
ACTIONS = ("create", "modify", "delete")


class ChangesetError(Exception):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _target(root: Path, relative: str, *, must_exist: bool) -> Path:
    root = root.resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise ChangesetError(f"{relative!r} escapes the project root")
    if must_exist and not target.is_file():
        raise ChangesetError(f"{relative!r} does not exist")
    if not must_exist and target.exists():
        raise ChangesetError(f"{relative!r} already exists")
    return target


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cs-", suffix=".tmp")
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


def _digest(payload: dict[str, Any]) -> str:
    return _sha(
        canonical_bytes(
            {
                "kind": payload["kind"],
                "rationale": payload["rationale"],
                "edits": [
                    {
                        "path": edit["path"],
                        "action": edit["action"],
                        "before_sha256": edit["before_sha256"],
                        "after_sha256": edit["after_sha256"],
                    }
                    for edit in payload["edits"]
                ],
            }
        )
    )


def propose(
    root: str | os.PathLike[str],
    edits: Iterable[dict[str, Any]],
    *,
    kind: str,
    rationale: str,
    signer: HybridSigner,
    tests: Iterable[Iterable[str]] = (),
    now: int | None = None,
) -> dict[str, Any]:
    if kind not in KINDS:
        raise ChangesetError(f"unknown change kind {kind!r}; expected one of {KINDS}")
    if not rationale.strip():
        raise ChangesetError("a changeset needs a rationale")
    project = Path(root)
    prepared: list[dict[str, Any]] = []
    seen: set[str] = set()
    for edit in edits:
        relative = str(edit.get("path", ""))
        action = str(edit.get("action", "modify"))
        if action not in ACTIONS:
            raise ChangesetError(f"unknown action {action!r}")
        if not relative or relative in seen:
            raise ChangesetError(f"duplicate or empty path {relative!r}")
        seen.add(relative)
        target = _target(project, relative, must_exist=action != "create")
        before = target.read_bytes() if action != "create" else b""
        if action == "delete":
            after = b""
            content = None
        else:
            content = str(edit.get("content", ""))
            if not content:
                raise ChangesetError(f"{relative!r} has no content")
            after = content.encode("utf-8")
        if action == "modify" and before == after:
            raise ChangesetError(f"{relative!r} would not change")
        prepared.append(
            {
                "path": relative,
                "action": action,
                "before_sha256": _sha(before) if action != "create" else "",
                "after_sha256": _sha(after),
                "content": content,
            }
        )
    if not prepared:
        raise ChangesetError("a changeset needs at least one edit")

    payload = {
        "kind": kind,
        "rationale": rationale,
        "tests": [list(command) for command in tests],
        "edits": prepared,
    }
    payload["digest"] = _digest(payload)
    issued = now_ms() if now is None else int(now)
    envelope = signer.sign(
        canonical_bytes(payload),
        domain=DOMAIN,
        proto_id=PROTO[0],
        proto_version=PROTO[1],
        issued_at_ms=issued,
    )
    return {"changeset": payload, "envelope": envelope}


def verify_changeset(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    payload = dict(document["changeset"])
    try:
        verifier.verify(
            document["envelope"],
            canonical_bytes(payload),
            expected_domain=DOMAIN,
            expected_proto=PROTO,
            now=now,
        )
    except SigError as exc:
        raise ChangesetError(f"changeset signature is not valid: {exc}") from exc
    if _digest(payload) != payload.get("digest"):
        raise ChangesetError("changeset digest does not match its edits")
    for edit in payload["edits"]:
        target = _target(Path(root), edit["path"], must_exist=edit["action"] != "create")
        current = _sha(target.read_bytes()) if target.is_file() else ""
        if current != edit["before_sha256"]:
            raise ChangesetError(f"{edit['path']!r} changed after the changeset was written")
    return payload


def _apply_edits(project: Path, payload: dict[str, Any]) -> None:
    for edit in payload["edits"]:
        target = project / edit["path"]
        if edit["action"] == "delete":
            target.unlink(missing_ok=True)
        else:
            _atomic_write(target, edit["content"].encode("utf-8"))


def review(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    *,
    timeout: float = 120.0,
    now: int | None = None,
) -> dict[str, Any]:
    payload = verify_changeset(document, verifier, root, now=now)
    source = Path(root).resolve()
    with tempfile.TemporaryDirectory(prefix="omnishield-changeset-") as raw:
        work = Path(raw) / "work"
        shutil.copytree(source, work, ignore=IGNORE)
        _apply_edits(work, payload)
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
        "digest": payload["digest"],
        "files": len(payload["edits"]),
        "tests": runs,
    }


def approve(
    report: dict[str, Any],
    approver: HybridSigner,
    *,
    approver_name: str,
    now: int | None = None,
) -> dict[str, Any]:
    if not report.get("ok"):
        raise ChangesetError("refusing to approve a changeset whose review failed")
    if not approver_name.strip():
        raise ChangesetError("an approval must name the human or service that granted it")
    issued = now_ms() if now is None else int(now)
    payload = {
        "digest": report["digest"],
        "files": report["files"],
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


def _restore(journal_path: Path, root: Path) -> None:
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    for entry in reversed(journal["entries"]):
        target = root / entry["path"]
        if entry["existed"]:
            _atomic_write(target, Path(entry["backup"]).read_bytes())
        elif target.exists():
            target.unlink()


def apply(
    document: dict[str, Any],
    approval: dict[str, Any],
    verifier: HybridVerifier,
    approver_public: PublicIdentity,
    root: str | os.PathLike[str],
    *,
    backup_dir: str | os.PathLike[str],
    health: Iterable[str] | None = None,
    timeout: float = 120.0,
    audit: AuditLog | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    payload = verify_changeset(document, verifier, root, now=now)
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
        raise ChangesetError(f"approval is not valid: {exc}") from exc
    if approval_payload.get("digest") != payload["digest"]:
        raise ChangesetError("the approval belongs to a different changeset")
    if not approval_payload.get("review_ok"):
        raise ChangesetError("the approval does not confirm a passing review")
    if verifier.identity.key_id == approver_public.key_id:
        raise ChangesetError("the proposer may not approve its own changeset")

    project = Path(root).resolve()
    journal_dir = Path(backup_dir) / payload["digest"][:12]
    journal_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for index, edit in enumerate(payload["edits"]):
        target = project / edit["path"]
        existed = target.is_file()
        backup = ""
        if existed:
            backup_path = journal_dir / f"{index}-{Path(edit['path']).name}.bak"
            backup_path.write_bytes(target.read_bytes())
            os.chmod(backup_path, 0o600)
            backup = str(backup_path)
        entries.append({"path": edit["path"], "existed": existed, "backup": backup})
    journal_path = journal_dir / "journal.json"
    journal_path.write_text(
        json.dumps({"digest": payload["digest"], "entries": entries}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(journal_path, 0o600)

    try:
        _apply_edits(project, payload)
    except Exception as exc:
        _restore(journal_path, project)
        raise ChangesetError(f"write failed, every file was restored: {exc}") from exc

    health_state = "skipped"
    if health is not None:
        command = list(health)
        try:
            completed = subprocess.run(
                command,
                cwd=project,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            _restore(journal_path, project)
            raise ChangesetError("health check timed out; every file was restored") from None
        if completed.returncode != 0:
            _restore(journal_path, project)
            tail = (completed.stdout + completed.stderr)[-400:]
            raise ChangesetError(
                f"health check failed, every file was restored: {tail}"
            )
        health_state = "passed"

    record = {
        "digest": payload["digest"],
        "kind": payload["kind"],
        "files": [edit["path"] for edit in payload["edits"]],
        "approver": approval_payload["approver"],
        "journal": str(journal_path),
        "health": health_state,
    }
    if audit is not None:
        audit.append("changeset.apply", record)
    return record


def rollback(
    journal: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    journal_path = Path(journal)
    if not journal_path.is_file():
        raise ChangesetError(f"journal not found: {journal_path}")
    project = Path(root).resolve()
    data = json.loads(journal_path.read_text(encoding="utf-8"))
    _restore(journal_path, project)
    record = {"digest": data["digest"], "restored": [entry["path"] for entry in data["entries"]]}
    if audit is not None:
        audit.append("changeset.rollback", record)
    return record
