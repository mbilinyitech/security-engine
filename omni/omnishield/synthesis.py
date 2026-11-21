"""Runtime tool creation with a static gate and a resource-limited sandbox.

A tool is accepted only if its source parses, imports nothing dangerous, never
touches dunder attributes, and defines `run(payload)`. It is then written to disk,
hashed and signed. Running it means a fresh interpreter with a minimal namespace,
CPU/memory/file/descriptor limits, a wall-clock timeout, and a network namespace
when the kernel permits it.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, SigError, now_ms

DOMAIN = "omnishield.synthesis"
PROTO = ("synthesis", 1)
RUNNER = Path(__file__).with_name("_sandbox_runner.py")
NAME = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
MAX_SOURCE = 64 * 1024

FORBIDDEN_IMPORTS = {
    "os",
    "sys",
    "subprocess",
    "socket",
    "shutil",
    "ctypes",
    "importlib",
    "pathlib",
    "pty",
    "signal",
    "multiprocessing",
    "threading",
    "pickle",
    "marshal",
    "code",
    "codeop",
    "resource",
    "gc",
}
FORBIDDEN_NAMES = {
    "eval",
    "exec",
    "compile",
    "open",
    "__import__",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "breakpoint",
    "input",
    "memoryview",
}


class SynthesisError(Exception):
    pass


def check_source(source: str) -> ast.Module:
    if not source.strip():
        raise SynthesisError("tool source is empty")
    if len(source.encode("utf-8")) > MAX_SOURCE:
        raise SynthesisError(f"tool source exceeds {MAX_SOURCE} bytes")
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as exc:
        raise SynthesisError(f"tool source does not parse: {exc}") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                    raise SynthesisError(f"import of {alias.name!r} is not allowed in a tool")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in FORBIDDEN_IMPORTS:
                raise SynthesisError(f"import from {node.module!r} is not allowed in a tool")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise SynthesisError(f"dunder attribute access {node.attr!r} is not allowed")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            raise SynthesisError(f"use of {node.id!r} is not allowed in a tool")
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    if "run" not in functions:
        raise SynthesisError("a tool must define run(payload)")
    return tree


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def synthesize(
    name: str,
    source: str,
    signer: HybridSigner,
    root: str | os.PathLike[str],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    if not NAME.match(name):
        raise SynthesisError("tool name must be lowercase letters, digits and underscores")
    check_source(source)
    directory = Path(root) / "tools"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{name}.py"
    data = source.encode("utf-8")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    payload = {
        "name": name,
        "path": f"tools/{name}.py",
        "sha256": _sha(data),
        "size": len(data),
        "created_ms": now_ms() if now is None else int(now),
    }
    envelope = signer.sign(
        canonical_bytes(payload),
        domain=DOMAIN,
        proto_id=PROTO[0],
        proto_version=PROTO[1],
        issued_at_ms=payload["created_ms"],
    )
    return {"tool": payload, "envelope": envelope}


def verify_tool(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    *,
    now: int | None = None,
) -> Path:
    payload = dict(document["tool"])
    try:
        verifier.verify(
            document["envelope"],
            canonical_bytes(payload),
            expected_domain=DOMAIN,
            expected_proto=PROTO,
            now=now,
        )
    except SigError as exc:
        raise SynthesisError(f"tool signature is not valid: {exc}") from exc
    path = (Path(root) / payload["path"]).resolve()
    root_path = Path(root).resolve()
    if root_path not in path.parents:
        raise SynthesisError("tool path escapes the tool directory")
    if not path.is_file():
        raise SynthesisError(f"tool file is missing: {payload['path']}")
    if _sha(path.read_bytes()) != payload["sha256"]:
        raise SynthesisError("tool file changed after it was signed")
    return path


def _limits() -> Any:
    def apply() -> None:  # pragma: no cover - runs in the child before exec
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


_UNSHARE: bool | None = None


def _can_unshare() -> bool:
    global _UNSHARE
    if _UNSHARE is None:
        _UNSHARE = False
        if os.name == "posix" and os.geteuid() == 0 and shutil.which("unshare"):
            probe = subprocess.run(
                ["unshare", "-n", "true"], capture_output=True, timeout=5, check=False
            )
            _UNSHARE = probe.returncode == 0
    return _UNSHARE


def _command(path: Path) -> tuple[list[str], bool]:
    base = [sys.executable, "-I", "-S", "-B", str(RUNNER), str(path)]
    if _can_unshare():
        return ["unshare", "-n", "--", *base], True
    return base, False


def run_tool(
    document: dict[str, Any],
    verifier: HybridVerifier,
    root: str | os.PathLike[str],
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
    now: int | None = None,
) -> dict[str, Any]:
    path = verify_tool(document, verifier, root, now=now)
    command, isolated = _command(path)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload or {}),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(path.parent),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            preexec_fn=_limits() if os.name == "posix" else None,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SynthesisError(f"tool exceeded the {timeout:g}s wall-clock limit") from exc
    duration = int((time.monotonic() - started) * 1000)
    try:
        response = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SynthesisError(f"tool produced invalid JSON: {completed.stdout[-300:]!r}") from exc
    if completed.returncode != 0 or "error" in response:
        message = response.get("error") or completed.stderr[-300:]
        raise SynthesisError(f"tool failed: {message}")
    return {
        "result": response.get("result"),
        "duration_ms": duration,
        "network_isolated": isolated,
        "limits": {"cpu_s": 2, "memory_mb": 256, "file_mb": 1, "wall_s": timeout},
    }
