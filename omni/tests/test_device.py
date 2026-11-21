import os
import subprocess
import sys
from pathlib import Path

import pytest

from omnishield.device import (
    DeviceError,
    bind_identity,
    require_tpm,
    tpm_available,
    tpm_path,
)
from omnishield.hybrid import HybridSigner

REPO = Path(__file__).resolve().parents[1]


def test_tpm_detection_is_consistent():
    assert isinstance(tpm_available(), bool)
    assert tpm_available() is (tpm_path() is not None)


def test_require_tpm_refuses_when_absent():
    if tpm_available():
        assert Path(require_tpm()).exists()
    else:
        with pytest.raises(DeviceError, match="no TPM device"):
            require_tpm()


def test_bind_identity_to_an_explicit_device(tmp_path):
    device = tmp_path / "tpmrm0"
    device.write_bytes(b"")
    signer = HybridSigner.generate()
    binding = bind_identity(signer.public_identity, tpm=str(device))
    assert binding["bound"] is True
    assert binding["device"] == str(device)
    assert binding["key_id"] == signer.public_identity.fingerprint


def test_bind_identity_refuses_a_missing_device(tmp_path):
    signer = HybridSigner.generate()
    with pytest.raises(DeviceError, match="does not exist"):
        bind_identity(signer.public_identity, tpm=str(tmp_path / "absent"))


def test_keygen_without_hardware_still_works(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "omnishield.cli", "keygen", "--out", str(tmp_path / "pub.json")],
        cwd=str(REPO),
        env={**os.environ, "OMNISHIELD_HOME": str(tmp_path / "home")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "pub.json").is_file()


def test_keygen_hardware_flag_refuses_without_a_tpm(tmp_path):
    if tpm_available():
        pytest.skip("this machine has a TPM")
    result = subprocess.run(
        [sys.executable, "-m", "omnishield.cli", "keygen", "--hardware"],
        cwd=str(REPO),
        env={**os.environ, "OMNISHIELD_HOME": str(tmp_path / "home")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "TPM" in result.stderr
