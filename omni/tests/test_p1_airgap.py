import pytest

from omnishield.hybrid import (
    HybridSigner,
    HybridVerifier,
    PayloadMismatch,
    SigError,
    now_ms,
)
from omnishield.p1_airgap import (
    BeaconRejected,
    DowngradeGuard,
    DowngradeRejected,
    NetworkProfile,
    ProfileError,
    enforce_plan,
    sign_profile,
    verify_profile,
)


@pytest.fixture()
def signer():
    return HybridSigner.generate()


@pytest.fixture()
def profile():
    return NetworkProfile(ssid="HQ", bssids=("aa:bb:cc:dd:ee:ff",), min_security="wpa3-sae")


@pytest.fixture()
def guard(signer, profile):
    verified = verify_profile(sign_profile(profile, signer), HybridVerifier(signer.public_identity))
    return DowngradeGuard(verified)


def test_signed_profile_roundtrip(signer, profile):
    document = sign_profile(profile, signer)
    verified = verify_profile(document, HybridVerifier(signer.public_identity))
    assert verified.ssid == "HQ"
    assert verified.not_after_ms > verified.not_before_ms


def test_tampered_profile_rejected(signer, profile):
    document = sign_profile(profile, signer)
    document["profile"]["ssid"] = "Evil"
    with pytest.raises(PayloadMismatch):
        verify_profile(document, HybridVerifier(signer.public_identity))


def test_expired_profile_rejected(signer, profile):
    document = sign_profile(profile, signer, ttl_ms=1_000, now=now_ms() - 60_000)
    with pytest.raises(SigError, match="expired"):
        verify_profile(document, HybridVerifier(signer.public_identity))


def test_downgrade_to_wpa2_rejected(guard):
    with pytest.raises(DowngradeRejected):
        guard.negotiate(["wpa2-psk"])


def test_legacy_offer_rejected(guard):
    with pytest.raises(DowngradeRejected):
        guard.negotiate(["wep", "open"])


def test_best_allowed_version_wins():
    profile = NetworkProfile(ssid="HQ", min_security="wpa2-psk", allowed_versions=("wpa2-psk", "wpa3-sae"))
    guard = DowngradeGuard(profile)
    assert guard.negotiate(["wpa2-psk", "wpa3-sae"]) == "wpa3-sae"
    assert guard.negotiate(["wpa2-psk"]) == "wpa2-psk"


def test_check_rejects_version_outside_allowlist(guard):
    with pytest.raises(DowngradeRejected):
        guard.check("wpa2-psk")


def test_pinned_beacon_accepted(guard):
    guard.check_beacon(ssid="HQ", bssid="aa:bb:cc:dd:ee:ff", security="wpa3-sae", protected_frame=True)


def test_unpinned_bssid_rejected(guard):
    with pytest.raises(BeaconRejected, match="not pinned"):
        guard.check_beacon(ssid="HQ", bssid="11:22:33:44:55:66", security="wpa3-sae", protected_frame=True)


def test_unprotected_beacon_rejected(guard):
    with pytest.raises(BeaconRejected, match="PMF"):
        guard.check_beacon(ssid="HQ", bssid="aa:bb:cc:dd:ee:ff", security="wpa3-sae", protected_frame=False)


def test_legacy_beacon_rejected(guard):
    with pytest.raises(BeaconRejected):
        guard.check_beacon(ssid="HQ", bssid="aa:bb:cc:dd:ee:ff", security="wpa2-psk", protected_frame=True)


def test_enforcement_plan_pins_sae_and_pmf(profile):
    plan = enforce_plan(profile)
    config = plan["wpa_supplicant.conf"]
    assert "key_mgmt=SAE" in config
    assert "ieee80211w=2" in config
    assert "bssid=aa:bb:cc:dd:ee:ff" in config
    assert "wep" not in config.lower()
    assert any("pmf 2" in command for command in plan["nmcli"])


def test_legacy_minimum_rejected():
    with pytest.raises(ProfileError):
        NetworkProfile(ssid="X", min_security="wep").validate()


def test_allowed_version_below_minimum_rejected():
    with pytest.raises(ProfileError):
        NetworkProfile(ssid="X", min_security="wpa3-sae", allowed_versions=("wpa2-psk",)).validate()


def test_malformed_bssid_rejected():
    with pytest.raises(ProfileError):
        NetworkProfile(ssid="X", bssids=("aa:bb",)).validate()
