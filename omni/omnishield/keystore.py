"""Key storage: file backend with strict permissions, TPM 2.0 backend when present.

The file backend is honest about being software: it reports origin="file". The
TPM backend seals the key material to the chip so it cannot be read off disk.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

DEFAULT_HOME = Path(os.environ.get("OMNISHIELD_HOME", str(Path.home() / ".omnishield")))
POSIX = os.name == "posix"


class KeyStoreError(Exception):
    pass


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically replace a state file with 0600 permissions on POSIX."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if POSIX:
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


class KeyStore(ABC):
    origin: str = "unknown"

    @abstractmethod
    def exists(self, name: str) -> bool: ...

    @abstractmethod
    def save(self, name: str, payload: bytes) -> None: ...

    @abstractmethod
    def load(self, name: str) -> bytes: ...

    def delete(self, name: str) -> None:
        raise KeyStoreError("this backend does not support deletion")


class FileKeyStore(KeyStore):
    origin = "file"
    permission_model = "posix-0700/0600" if POSIX else "os-default"

    def __init__(self, directory: str | os.PathLike[str] | None = None):
        self.directory = Path(directory) if directory is not None else DEFAULT_HOME / "keys"

    def _ensure_dir(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not POSIX:
            return
        mode = self.directory.stat().st_mode & 0o777
        if mode & 0o077:
            raise KeyStoreError(f"key directory {self.directory} is group/world accessible ({oct(mode)})")

    def _path(self, name: str) -> Path:
        if not name or "/" in name or name.startswith("."):
            raise KeyStoreError(f"invalid key name: {name!r}")
        return self.directory / f"{name}.key"

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def save(self, name: str, payload: bytes) -> None:
        self._ensure_dir()
        target = self._path(name)
        fd, tmp_name = tempfile.mkstemp(dir=self.directory, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if POSIX:
                os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, target)
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        if POSIX and target.stat().st_mode & 0o077:
            raise KeyStoreError(f"key file {target} is group/world accessible")

    def load(self, name: str) -> bytes:
        path = self._path(name)
        if not path.exists():
            raise KeyStoreError(f"no key named {name!r} in {self.directory}")
        if POSIX and path.stat().st_mode & 0o077:
            raise KeyStoreError(f"refusing to read {path}: permissions are too open")
        return path.read_bytes()

    def delete(self, name: str) -> None:
        path = self._path(name)
        if path.exists():
            path.unlink()


class Tpm2KeyStore(KeyStore):
    """Seals key material to the local TPM 2.0 chip via tpm2-tools."""

    origin = "tpm2"
    TOOLS = ("tpm2_createprimary", "tpm2_create", "tpm2_load", "tpm2_unseal")

    def __init__(self, directory: str | os.PathLike[str] | None = None):
        self.directory = Path(directory) if directory is not None else DEFAULT_HOME / "tpm"

    @staticmethod
    def available() -> bool:
        if not all(shutil.which(tool) for tool in Tpm2KeyStore.TOOLS):
            return False
        return Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists()

    def _paths(self, name: str) -> tuple[Path, Path]:
        if not name or "/" in name or name.startswith("."):
            raise KeyStoreError(f"invalid key name: {name!r}")
        return self.directory / f"{name}.pub", self.directory / f"{name}.priv"

    def _run(self, *args: str) -> None:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise KeyStoreError(f"{args[0]} failed: {result.stderr.strip()}")

    def exists(self, name: str) -> bool:
        return all(path.exists() for path in self._paths(name))

    def save(self, name: str, payload: bytes) -> None:
        if not self.available():
            raise KeyStoreError("TPM 2.0 device or tpm2-tools not available")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        pub, priv = self._paths(name)
        with tempfile.TemporaryDirectory(dir=self.directory) as work:
            workdir = Path(work)
            data = workdir / "data.bin"
            data.write_bytes(payload)
            primary = workdir / "primary.ctx"
            self._run("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", str(primary))
            self._run(
                "tpm2_create", "-C", str(primary), "-g", "sha256",
                "-u", str(workdir / "key.pub"), "-r", str(workdir / "key.priv"),
                "-i", str(data),
            )
            os.replace(workdir / "key.pub", pub)
            os.replace(workdir / "key.priv", priv)
        data.unlink(missing_ok=True)

    def load(self, name: str) -> bytes:
        if not self.available():
            raise KeyStoreError("TPM 2.0 device or tpm2-tools not available")
        pub, priv = self._paths(name)
        with tempfile.TemporaryDirectory(dir=self.directory) as work:
            workdir = Path(work)
            primary = workdir / "primary.ctx"
            key_ctx = workdir / "key.ctx"
            out = workdir / "out.bin"
            self._run("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", str(primary))
            self._run("tpm2_load", "-C", str(primary), "-u", str(pub), "-r", str(priv), "-c", str(key_ctx))
            self._run("tpm2_unseal", "-c", str(key_ctx), "-o", str(out))
            return out.read_bytes()


def open_keystore(backend: str = "auto", directory: str | os.PathLike[str] | None = None) -> KeyStore:
    if backend == "file":
        return FileKeyStore(directory)
    if backend == "tpm2":
        return Tpm2KeyStore(directory)
    if backend != "auto":
        raise KeyStoreError(f"unknown keystore backend: {backend!r}")
    return Tpm2KeyStore(directory) if Tpm2KeyStore.available() else FileKeyStore(directory)
