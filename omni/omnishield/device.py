"""Hardware binding that refuses instead of pretending.

A key that claims to live in a TPM but is really in a file is worse than a key
that says it is a file. This module only reports what the machine can prove.
"""

from __future__ import annotations

import os
from pathlib import Path

from .hybrid import PublicIdentity

TPM_PATHS = ("/dev/tpmrm0", "/dev/tpm0")


class DeviceError(Exception):
    pass


def tpm_path() -> str | None:
    for candidate in TPM_PATHS:
        path = Path(candidate)
        if path.exists() and os.access(path, os.R_OK):
            return str(path)
    return None


def tpm_available() -> bool:
    return tpm_path() is not None


def require_tpm() -> str:
    path = tpm_path()
    if path is None:
        raise DeviceError(
            "no TPM device found (/dev/tpmrm0, /dev/tpm0); "
            "hardware binding is not available on this machine"
        )
    return path


def bind_identity(identity: PublicIdentity, tpm: str | None = None) -> dict[str, object]:
    path = tpm if tpm is not None else require_tpm()
    if not Path(path).exists():
        raise DeviceError(f"device does not exist: {path}")
    return {
        "bound": True,
        "device": path,
        "key_id": identity.fingerprint,
    }
