"""Bridge from Omni to Sovereign's capability pipeline.

Sovereign (`mbilinyitech/security-engine`) issues capabilities with hybrid
post-quantum signatures: ECDSA P-384 AND ML-DSA-87, both required. Omni does not
re-implement that; it calls the operator CLI and checks the result.

Pipeline: ca init (root) -> ca init (device) -> ca certify -> enroll -> host ->
verify. Every stage prints `key=value` lines, which we parse. If the binary is
missing the bridge says so instead of pretending.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class SovereignError(Exception):
    pass


def binary() -> Path:
    override = os.environ.get("SOVEREIGN_BRIDGE")
    candidates = []
    if override:
        candidates.append(Path(override))
    candidates.append(Path(__file__).resolve().parent.parent.parent / "target" / "release" / "sovereign-bridge")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("sovereign-bridge")
    if found:
        return Path(found)
    raise SovereignError("sovereign-bridge is not built; run cargo build --release -p sovereign-bridge")


def run(args: Sequence[str], *, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [str(binary()), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise SovereignError(f"{' '.join(args)} failed: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed


def pairs(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() and value.strip():
            found[key.strip()] = value.strip()
    return found


def status() -> dict[str, Any]:
    path = binary()
    completed = subprocess.run([str(path), "--help"], capture_output=True, text=True, timeout=30, check=False)
    commands = sorted(
        {
            line.split()[1]
            for line in completed.stdout.splitlines()
            if line.strip().startswith("sovereign-bridge ") and len(line.split()) > 1
        }
    )
    return {"available": True, "path": str(path), "commands": commands, "help_exit": completed.returncode}


def pipeline(*, rights: str = "telemetry", nonce: str = "00" * 32, now: int | None = None) -> dict[str, Any]:
    if not rights.strip():
        raise SovereignError("rights cannot be empty")
    moment = int(time.time() if now is None else now)
    session_key = "aa" * 32
    started = time.perf_counter()

    root = pairs(run(["ca", "init"]).stdout)
    device = pairs(run(["ca", "init"]).stdout)
    root_seed = f"{root['root-ecdsa-seed']}:{root['root-mldsa-seed']}"
    device_seed = f"{device['root-ecdsa-seed']}:{device['root-mldsa-seed']}"
    device_public = device["root-public-key"]

    cert = pairs(run(["ca", "certify", root_seed, device_public, rights]).stdout)
    certificate = cert.get("device-cert") or cert.get("cert") or cert.get("certificate")
    if not certificate:
        raise SovereignError(f"ca certify returned no certificate: {sorted(cert)}")

    claim = pairs(run(["enroll", root["root-public-key"], certificate, nonce, device_seed]).stdout)
    attestation = claim.get("claim") or claim.get("attestation")
    if not attestation:
        raise SovereignError(f"enroll returned no claim: {sorted(claim)}")

    grant = pairs(run(["host", root_seed, certificate, nonce, attestation, session_key, str(moment)]).stdout)
    capability = grant.get("grant") or grant.get("capability")
    if not capability:
        raise SovereignError(f"host returned no grant: {sorted(grant)}")

    verified = run(["verify", root["root-public-key"], capability, str(moment)])
    return {
        "ok": True,
        "rights": rights,
        "nonce": nonce,
        "at": moment,
        "stages": ["ca init", "ca init", "ca certify", "enroll", "host", "verify"],
        "grant_bytes": len(capability) // 2,
        "verify_stdout": verified.stdout.strip()[:400],
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def verify_grant(grant_hex: str, root_public_hex: str, *, now: int | None = None) -> dict[str, Any]:
    moment = int(time.time() if now is None else now)
    completed = run(["verify", root_public_hex, grant_hex, str(moment)])
    text = completed.stdout.strip()
    return {"ok": "valid" in text.lower() or "ok" in text.lower(), "stdout": text[:400], "at": moment}
