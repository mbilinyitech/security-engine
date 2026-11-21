"""Client for the Rust organism core, plus signed state records.

The core is a separate process that speaks line-delimited JSON-RPC 2.0. Keeping
it out of process means the Python side never links Rust code, and the same
binary can be driven by any other language.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Self

from .canonical import canonical_bytes
from .hybrid import HybridSigner, HybridVerifier, PublicIdentity, now_ms

REPO_ROOT = Path(__file__).resolve().parents[1]
CRATE_DIR = REPO_ROOT / "organism"
STATE_DOMAIN = "omnishield.organism.state"
STATE_PROTO = ("organism-state", 1)


class OrganismError(Exception):
    pass


def binary_path(explicit: str | os.PathLike[str] | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("ORGANISM_BIN")
    if env:
        candidates.append(Path(env))
    candidates.append(CRATE_DIR / "target" / "release" / "organism")
    candidates.append(CRATE_DIR / "target" / "debug" / "organism")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def build_binary(*, release: bool = True) -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise OrganismError(
            "cargo not found: install Rust from https://rustup.rs to build the organism core"
        )
    command = [cargo, "build", "--manifest-path", str(CRATE_DIR / "Cargo.toml")]
    if release:
        command.append("--release")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise OrganismError(f"cargo build failed:\n{result.stderr.strip()[-800:]}")
    found = binary_path()
    if found is None:
        raise OrganismError("cargo reported success but the binary is missing")
    return found


class OrganismClient:
    """A live JSON-RPC session with the organism core."""

    def __init__(
        self,
        binary: str | os.PathLike[str] | None = None,
        timeout: float = 30.0,
    ):
        path = binary_path(binary)
        if path is None:
            raise OrganismError(
                "organism binary not found: run `python3 -m omnishield.organism build` "
                "or set ORGANISM_BIN"
            )
        self.path = path
        self.timeout = timeout
        self._next_id = 0
        self._process = subprocess.Popen(
            [str(path), "rpc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if self._process.poll() is not None:
            raise OrganismError(f"organism core is not running: {self._stderr_tail()}")
        self._next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params or {},
        }
        stdin = self._process.stdin
        stdout = self._process.stdout
        if stdin is None or stdout is None:
            raise OrganismError("organism core pipes are closed")
        stdin.write(json.dumps(request) + "\n")
        stdin.flush()
        line = stdout.readline()
        if not line:
            raise OrganismError(f"organism core closed the stream: {self._stderr_tail()}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OrganismError(f"organism core sent invalid JSON: {line!r}") from exc
        if response.get("id") != self._next_id:
            raise OrganismError(f"response id mismatch: {response.get('id')}")
        if "error" in response:
            error = response["error"]
            raise OrganismError(f"{error.get('code')}: {error.get('message')}")
        return response["result"]

    def discover(self) -> dict[str, Any]:
        return self.call("organism.discover")

    def state(self) -> dict[str, Any]:
        return self.call("organism.state")

    def _stderr_tail(self) -> str:
        stderr = self._process.stderr
        if stderr is None or self._process.poll() is None:
            return "no stderr"
        try:
            return stderr.read()[-500:].strip() or "no stderr"
        except (OSError, ValueError):
            return "no stderr"

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def sign_state(
    client: OrganismClient,
    signer: HybridSigner,
    *,
    ttl_ms: int = 60_000,
) -> dict[str, Any]:
    """Wrap the core's self-description in a hybrid signature."""
    payload = {"state": client.state(), "observed_at_ms": now_ms()}
    envelope = signer.sign(
        canonical_bytes(payload),
        domain=STATE_DOMAIN,
        proto_id=STATE_PROTO[0],
        proto_version=STATE_PROTO[1],
        ttl_ms=ttl_ms,
    )
    return {"payload": payload, "envelope": envelope}


def verify_state(
    document: dict[str, Any],
    identity: PublicIdentity,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    payload = dict(document["payload"])
    HybridVerifier(identity).verify(
        document["envelope"],
        canonical_bytes(payload),
        expected_domain=STATE_DOMAIN,
        expected_proto=STATE_PROTO,
        now=now,
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m omnishield.organism")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="compile the Rust core")
    build.add_argument("--debug", action="store_true")
    sub.add_parser("discover", help="print the method catalog")
    sub.add_parser("state", help="print the core state")
    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            path = build_binary(release=not args.debug)
            print(f"built {path}")
            return 0
        with OrganismClient() as client:
            result = client.discover() if args.command == "discover" else client.state()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except OrganismError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
