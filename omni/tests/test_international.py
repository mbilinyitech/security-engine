import os
import subprocess
import sys
from pathlib import Path

import pytest

from omnishield.hybrid import HybridSigner, HybridVerifier
from omnishield.p1_airgap import (
    NetworkProfile,
    ProfileError,
    enforce_plan,
    quote_ssid,
    sign_profile,
    verify_profile,
)
from omnishield.p4_allowlist import AllowList, build_manifest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture()
def signer():
    return HybridSigner.generate()


def _cli(arguments, env_extra=None, home=None):
    env = dict(os.environ)
    env["OMNISHIELD_HOME"] = str(home) if home else str(REPO / ".tmp-home")
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "omnishield.cli", *arguments],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_unicode_ssid_survives_signing(signer):
    ssid = "Mtandao wa Ofisi – 東京"
    document = sign_profile(NetworkProfile(ssid=ssid, bssids=("aa:bb:cc:dd:ee:ff",)), signer)
    verified = verify_profile(document, HybridVerifier(signer.public_identity))
    assert verified.ssid == ssid
    assert ssid in enforce_plan(verified)["wpa_supplicant.conf"]


def test_ssid_cannot_inject_supplicant_directives():
    with pytest.raises(ProfileError):
        NetworkProfile(ssid='x"\nkey_mgmt=NONE\nnetwork={').validate()
    with pytest.raises(ProfileError):
        quote_ssid("a\nnetwork={")
    assert quote_ssid('say "hi" \\ ok') == '"say \\"hi\\" \\\\ ok"'


def test_ssid_length_and_control_characters():
    with pytest.raises(ProfileError, match="32"):
        NetworkProfile(ssid="x" * 33).validate()
    with pytest.raises(ProfileError, match="control"):
        NetworkProfile(ssid="a\x00b").validate()


def test_unicode_filenames_in_manifest(tmp_path, signer):
    name = "mod-ya-mkutano-東京-é.py"
    (tmp_path / name).write_text("VALUE = 'salama'\n", encoding="utf-8")
    document = build_manifest([tmp_path / name], signer, base_dir=tmp_path)
    allow = AllowList(document, HybridVerifier(signer.public_identity))
    assert allow.load_module(name).VALUE == "salama"


def test_cli_handles_unicode_arguments_in_c_locale(tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "hati-東京-é.txt"
    target.write_text("maudhui\n", encoding="utf-8")
    locale = {"LC_ALL": "C", "LANG": "C"}
    assert _cli(["keygen", "--out", str(tmp_path / "pub.json")], locale, home).returncode == 0
    assert _cli(["sign", str(target), "--out", str(tmp_path / "sig.json")], locale, home).returncode == 0
    result = _cli(["verify", str(target), str(tmp_path / "sig.json")], locale, home)
    assert result.returncode == 0, result.stderr


def test_timestamps_are_timezone_independent(tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "doc.txt"
    target.write_text("x", encoding="utf-8")
    east = {"TZ": "Pacific/Kiritimati"}
    west = {"TZ": "America/Anchorage"}
    assert _cli(["keygen", "--out", str(tmp_path / "pub.json")], east, home).returncode == 0
    assert _cli(["sign", str(target), "--out", str(tmp_path / "sig.json")], east, home).returncode == 0
    result = _cli(["verify", str(target), str(tmp_path / "sig.json")], west, home)
    assert result.returncode == 0, result.stderr


def test_unicode_identity_name_can_be_pinned(tmp_path):
    from omnishield.keystore import FileKeyStore
    from omnishield.p2_identity import DeviceIdentity, PinStore, verify_response

    device = DeviceIdentity.create(FileKeyStore(tmp_path / "keys"), "simu")
    pins = PinStore(tmp_path / "pins.json")
    challenge = b"\x09" * 32
    verify_response(
        device.respond(challenge, "malipo"),
        device.identity,
        server_nonce=challenge,
        expected_context="malipo",
        pins=pins,
        pin_name="amina@mkoa.go.tz",
    )
    assert pins.get("amina@mkoa.go.tz") == device.device_id


def test_cli_verification_is_idempotent(tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "hati.txt"
    target.write_text("x", encoding="utf-8")
    assert _cli(["keygen", "--out", str(tmp_path / "pub.json")], None, home).returncode == 0
    assert _cli(["sign", str(target), "--out", str(tmp_path / "sig.json")], None, home).returncode == 0
    first = _cli(["verify", str(target), str(tmp_path / "sig.json")], None, home)
    second = _cli(["verify", str(target), str(tmp_path / "sig.json")], None, home)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr


def test_cli_replay_guard_is_opt_in(tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "hati.txt"
    target.write_text("x", encoding="utf-8")
    assert _cli(["keygen", "--out", str(tmp_path / "pub.json")], None, home).returncode == 0
    assert _cli(["sign", str(target), "--out", str(tmp_path / "sig.json")], None, home).returncode == 0
    first = _cli(["verify", str(target), str(tmp_path / "sig.json"), "--replay"], None, home)
    second = _cli(["verify", str(target), str(tmp_path / "sig.json"), "--replay"], None, home)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 2, second.stderr
