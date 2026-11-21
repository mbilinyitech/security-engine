"""Protocol 1: strict air-gap and anti-legacy enforcement.

What is enforced here is the part that a host can actually enforce: a signed
network profile that pins SSID, BSSID, minimum security, and the exact protocol
version; a downgrade guard that refuses anything below the pin; and a beacon
gate that drops unprotected or unknown access points before association.

Beacon frames themselves cannot carry a 2.4 kB ML-DSA signature, so the trust
anchor is the signed profile plus 802.11w protected management frames and BSSID
pinning - the combination that actually stops evil-twin and deauth attacks.
"""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from .canonical import canonical_bytes
from .hybrid import (
    HybridSigner,
    HybridVerifier,
    SigError,
    now_ms,
    proto_lock,
)

DOMAIN = "omnishield.p1.network"
PROTO_ID = "wifi-profile"
PROTO_VERSION = 1

SECURITY_RANK = {
    "open": 0,
    "wep": 1,
    "wpa": 2,
    "wpa2-psk": 3,
    "wpa2-eap": 3,
    "wpa3-sae": 4,
    "wpa3-enterprise": 5,
}
LEGACY_SECURITY = frozenset({"open", "wep", "wpa"})


class ProfileError(SigError):
    pass


class DowngradeRejected(ProfileError):
    pass


class BeaconRejected(ProfileError):
    pass


@dataclass(frozen=True)
class NetworkProfile:
    ssid: str
    bssids: tuple[str, ...] = ()
    min_security: str = "wpa3-sae"
    allowed_versions: tuple[str, ...] = ("wpa3-sae",)
    require_pmf: bool = True
    not_before_ms: int = 0
    not_after_ms: int = 0

    def validate(self) -> None:
        if not self.ssid:
            raise ProfileError("ssid must not be empty")
        raw = self.ssid.encode("utf-8")
        if len(raw) > 32:
            raise ProfileError(f"ssid is {len(raw)} bytes; 802.11 allows at most 32")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in self.ssid):
            raise ProfileError("ssid must not contain control characters")
        if self.min_security not in SECURITY_RANK:
            raise ProfileError(f"unknown minimum security: {self.min_security!r}")
        if self.min_security in LEGACY_SECURITY:
            raise ProfileError("minimum security may not be a legacy mode")
        if not self.allowed_versions:
            raise ProfileError("allowed_versions must not be empty")
        for version in self.allowed_versions:
            if version not in SECURITY_RANK:
                raise ProfileError(f"unknown allowed version: {version!r}")
            if SECURITY_RANK[version] < SECURITY_RANK[self.min_security]:
                raise ProfileError(
                    f"allowed version {version!r} is below the declared minimum {self.min_security!r}"
                )
        for bssid in self.bssids:
            parts = bssid.split(":")
            if len(parts) != 6 or any(len(part) != 2 for part in parts):
                raise ProfileError(f"malformed BSSID: {bssid!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssids": list(self.bssids),
            "min_security": self.min_security,
            "allowed_versions": list(self.allowed_versions),
            "require_pmf": self.require_pmf,
            "not_before_ms": self.not_before_ms,
            "not_after_ms": self.not_after_ms,
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> NetworkProfile:
        profile = cls(
            ssid=str(doc["ssid"]),
            bssids=tuple(doc.get("bssids", ())),
            min_security=str(doc.get("min_security", "wpa3-sae")),
            allowed_versions=tuple(doc.get("allowed_versions", ("wpa3-sae",))),
            require_pmf=bool(doc.get("require_pmf", True)),
            not_before_ms=int(doc.get("not_before_ms", 0)),
            not_after_ms=int(doc.get("not_after_ms", 0)),
        )
        profile.validate()
        return profile


def sign_profile(
    profile: NetworkProfile,
    signer: HybridSigner,
    *,
    ttl_ms: int = 7 * 24 * 60 * 60 * 1000,
    now: int | None = None,
) -> dict[str, Any]:
    profile.validate()
    issued = now_ms() if now is None else int(now)
    bound = replace(profile, not_before_ms=issued, not_after_ms=issued + ttl_ms)
    payload = canonical_bytes(bound.to_dict())
    envelope = signer.sign(
        payload,
        domain=DOMAIN,
        proto_id=PROTO_ID,
        proto_version=PROTO_VERSION,
        ttl_ms=ttl_ms,
        issued_at_ms=issued,
    )
    return {"profile": bound.to_dict(), "envelope": envelope}


def verify_profile(
    document: Mapping[str, Any],
    verifier: HybridVerifier,
    *,
    replay: Any = None,
    now: int | None = None,
) -> NetworkProfile:
    profile = NetworkProfile.from_dict(document["profile"])
    payload = canonical_bytes(profile.to_dict())
    verifier.verify(
        document["envelope"],
        payload,
        expected_domain=DOMAIN,
        expected_proto=(PROTO_ID, PROTO_VERSION),
        replay=replay,
        now=now,
    )
    current = now_ms() if now is None else int(now)
    if profile.not_before_ms > current:
        raise ProfileError("network profile is not valid yet")
    if profile.not_after_ms < current:
        raise ProfileError("network profile has expired")
    return profile


class DowngradeGuard:
    """Fail-closed negotiation: no match means no connection."""

    def __init__(self, profile: NetworkProfile):
        profile.validate()
        self.profile = profile
        self.negotiated: str | None = None

    def negotiate(self, offered: Iterable[str]) -> str:
        candidates = [v for v in offered if v in self.profile.allowed_versions]
        if not candidates:
            raise DowngradeRejected(
                f"no allowed version offered; refused {sorted(set(offered))!r}"
            )
        best = max(candidates, key=lambda v: SECURITY_RANK[v])
        if SECURITY_RANK[best] < SECURITY_RANK[self.profile.min_security]:
            raise DowngradeRejected(
                f"peer forced {best!r} below the pinned minimum {self.profile.min_security!r}"
            )
        self.negotiated = best
        return best

    def check(self, version: str) -> None:
        if version not in self.profile.allowed_versions:
            raise DowngradeRejected(f"version {version!r} is not in the signed allow-list")
        if SECURITY_RANK.get(version, -1) < SECURITY_RANK[self.profile.min_security]:
            raise DowngradeRejected(
                f"version {version!r} is below the pinned minimum {self.profile.min_security!r}"
            )

    def lock_hash(self, version: str | None = None) -> str:
        return proto_lock(f"wifi/{version or self.negotiated}", PROTO_VERSION)

    def check_beacon(
        self,
        *,
        ssid: str,
        bssid: str,
        security: str,
        protected_frame: bool,
    ) -> None:
        if ssid != self.profile.ssid:
            raise BeaconRejected(f"unexpected SSID {ssid!r}")
        if self.profile.bssids and bssid.lower() not in {b.lower() for b in self.profile.bssids}:
            raise BeaconRejected(f"BSSID {bssid!r} is not pinned in the signed profile")
        if security in LEGACY_SECURITY:
            raise BeaconRejected(f"legacy security {security!r} is refused outright")
        if security not in self.profile.allowed_versions:
            raise BeaconRejected(f"security {security!r} is not in the signed allow-list")
        if self.profile.require_pmf and not protected_frame:
            raise BeaconRejected("management frames are unprotected (PMF required)")


def quote_ssid(ssid: str) -> str:
    """Quote an SSID for wpa_supplicant without letting it inject directives.

    SSIDs are attacker-controlled and may contain quotes, backslashes, or UTF-8,
    so every value is escaped rather than interpolated raw.
    """
    escaped = ssid.replace("\\", "\\\\").replace('"', '\\"')
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in escaped):
        raise ProfileError("ssid must not contain control characters")
    return f'"{escaped}"'


def _check_interface(interface: str) -> str:
    if not interface or len(interface) > 15 or not all(ch.isalnum() or ch in "._-" for ch in interface):
        raise ProfileError(f"invalid interface name: {interface!r}")
    return interface


def enforce_plan(profile: NetworkProfile, interface: str = "wlan0") -> dict[str, Any]:
    """Concrete configuration a host applies to make the profile real."""
    profile.validate()
    interface = _check_interface(interface)
    blocks = []
    targets = profile.bssids or ("",)
    for bssid in targets:
        lines = [
            "network={",
            f"    ssid={quote_ssid(profile.ssid)}",
            "    key_mgmt=SAE" if profile.min_security == "wpa3-sae" else "    key_mgmt=WPA-EAP",
            "    proto=RSN",
            "    pairwise=CCMP",
            "    group=CCMP",
            f"    ieee80211w={2 if profile.require_pmf else 0}",
            "    sae_pwe=2",
            "    sae_confirm_constant_time=1",
        ]
        if bssid:
            lines.append(f"    bssid={bssid}")
        lines.append("}")
        blocks.append("\n".join(lines))
    supplicant = "\n\n".join(blocks) + "\n"
    nmcli = [
        "nmcli radio wifi on",
        f"nmcli device set {interface} managed yes",
        "nmcli connection delete <any-wep-or-wpa-connection>",
        "nmcli connection modify <ssid-connection> 802-11-wireless-security.key-mgmt sae",
        "nmcli connection modify <ssid-connection> 802-11-wireless-security.pmf 2",
        f"nmcli connection modify <ssid-connection> 802-11-wireless.bssid {profile.bssids[0] if profile.bssids else '<pinned-bssid>'}",
    ]
    iw = [
        f"iw dev {interface} set power_save off",
        "iw event -t  # watch for deauth/Disassoc frames from unpinned BSSIDs",
    ]
    return {
        "wpa_supplicant.conf": supplicant,
        "nmcli": nmcli,
        "iw": iw,
        "notes": [
            (
                "Beacon frames cannot carry ML-DSA signatures; trust comes from the signed "
                "profile plus 802.11w PMF and BSSID pinning."
            ),
            "Legacy modes (open/WEP/WPA) are refused by policy, not negotiated downward.",
            f"Apply with: wpa_supplicant -i {interface} -c wpa_supplicant.conf -D nl80211",
        ],
    }


def profile_digest(profile: NetworkProfile) -> str:
    return hashlib.sha256(canonical_bytes(profile.to_dict())).hexdigest()


def new_ssid_nonce() -> bytes:
    return secrets.token_bytes(16)
