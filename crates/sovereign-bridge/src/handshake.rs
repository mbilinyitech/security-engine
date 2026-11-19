//! The plug-in handshake: how a newly attached device earns the right to talk to the kernel.
//!
//! The state machine is deliberately linear and irreversible. A device that fails any step is
//! dropped, and the only way back in is to be physically re-attached, which starts a fresh
//! challenge. There is no "retry" edge, no "already known device" shortcut, and no way to skip
//! attestation by presenting a cached token — a token is bound to the nonce of the session that
//! produced it.
//!
//! ```text
//! Quarantined --(bridge issues challenge)--> Challenged
//! Challenged  --(device signs challenge + claims rights)--> Attested
//! Attested    --(bridge narrows rights, mints token)--> Active
//! Active      --(kernel wipes / link closes)--> Revoked
//! any         --(any failure)--> Rejected
//! ```
//!
//! Two invariants matter more than the happy path:
//!
//! 1. **Rights never widen.** The granted rights are the intersection of what the device asked
//!    for, what its certificate permits, and what the policy allows. A sensor that asks for
//!    `NET_EGRESS` still gets `SENSOR_READ` only.
//! 2. **A device certificate is not a session.** Holding a valid certificate proves identity,
//!    not liveness. Only a signature over the *fresh* challenge proves the holder is present
//!    right now, which is what stops a replay of a captured handshake.

use sovereign_crypto::{labels, CryptoError, HybridSignature, HybridVerifyingKey};
use sovereign_ipc::{CapabilityToken, Rights};

/// Longest a device may take to answer a challenge before we stop waiting for it.
pub const CHALLENGE_TTL_SECS: u64 = 30;

/// Hard ceiling on any capability we mint, regardless of what a device asks for.
///
/// `ADMIN` is excluded on purpose: a hot-plugged peripheral must never be able to reflash,
/// revoke, or wipe the platform it is attached to. Administration happens out-of-band through a
/// separate, physically authenticated path.
pub const PLUGIN_RIGHTS_CEILING: Rights = Rights::SENSOR_READ
    .union(Rights::TELEMETRY_WRITE)
    .union(Rights::NET_EGRESS)
    .union(Rights::CRYPTO_OP);

/// Default session lifetime for a plug-in capability.
pub const DEFAULT_SESSION_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Attached, isolated by IOMMU, cannot yet touch memory or the network.
    Quarantined,
    /// We sent a nonce; waiting for a signed response.
    Challenged,
    /// The device proved possession of its key over our nonce.
    Attested,
    /// A capability token was minted and handed to the kernel.
    Active,
    /// Terminal. The device must be physically re-attached to try again.
    Rejected,
    /// Session ended cleanly; keys are gone.
    Revoked,
}

/// What a device asks for when it answers the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationClaim {
    /// Stable device identity, e.g. hash of the silicon identity plus slot.
    pub device_id: [u8; 16],
    /// Rights the device would like. Subject to narrowing, never trusted as-is.
    pub requested_rights: Rights,
    /// The device's hybrid public key.
    pub device_key: HybridVerifyingKey,
    /// Signature over `(domain, nonce || device_id || rights)`.
    pub signature: HybridSignature,
}

/// A device's long-term certificate, as issued by the Sovereign Root CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub device_id: [u8; 16],
    pub device_key: HybridVerifyingKey,
    /// The widest set of rights this *model* of device may ever hold.
    pub max_rights: Rights,
    /// Root CA signature over the fields above, so the bridge need not trust the device's own
    /// claim about its ceiling.
    pub root_signature: HybridSignature,
}

impl DeviceCertificate {
    /// The bytes the root CA signs. Order and framing are fixed; changing them breaks every
    /// issued certificate, which is the correct behaviour for a wire-format change.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 4 + 97 + 2592);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.max_rights.bits().to_be_bytes());
        out.extend_from_slice(&self.device_key.ecdsa);
        out.extend_from_slice(&self.device_key.mldsa);
        out
    }
}

/// Bytes a device signs to answer a challenge.
///
/// The nonce comes first so that no two sessions can produce the same payload, and the
/// requested rights are inside the signature so a man-in-the-middle cannot escalate them.
pub fn attestation_payload(nonce: &[u8; 32], device_id: &[u8; 16], requested: Rights) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 16 + 4);
    out.extend_from_slice(nonce);
    out.extend_from_slice(device_id);
    out.extend_from_slice(&requested.bits().to_be_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// The caller tried a transition the state machine does not allow.
    IllegalTransition {
        from: HandshakeState,
        to: HandshakeState,
    },
    /// The device's certificate is not signed by the root CA.
    UntrustedCertificate,
    /// The certificate is valid but does not cover this device id.
    CertificateMismatch,
    /// The attestation signature did not verify over our nonce.
    BadAttestation,
    /// The device took too long, or the challenge was already used.
    ChallengeExpired,
    /// The capability itself is outside its validity period.
    CapabilityExpired,
    /// The device's certificate does not permit even the narrowed rights.
    RightsNotPermitted,
    /// The narrowed rights came out empty, so there is nothing to grant.
    NoRightsGranted,
    /// Clock went backwards; refuse rather than issue a token with a nonsense lifetime.
    ClockError,
    /// Crypto layer refused.
    Crypto(CryptoError),
}

impl From<CryptoError> for HandshakeError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal transition {from:?} -> {to:?}")
            }
            Self::UntrustedCertificate => write!(f, "device certificate not trusted"),
            Self::CertificateMismatch => write!(f, "certificate does not match device"),
            Self::BadAttestation => write!(f, "attestation signature invalid"),
            Self::ChallengeExpired => write!(f, "challenge expired or already used"),
            Self::CapabilityExpired => write!(f, "capability expired or not yet valid"),
            Self::RightsNotPermitted => write!(f, "requested rights exceed certificate"),
            Self::NoRightsGranted => write!(f, "no rights survived narrowing"),
            Self::ClockError => write!(f, "system clock is not monotonic"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// A live handshake. Consumes itself on success so a session cannot be re-derived from a
/// half-finished handshake value.
#[derive(Debug)]
pub struct Handshake {
    state: HandshakeState,
    nonce: [u8; 32],
    issued_at: u64,
    /// Set once the challenge has been answered, so it cannot be answered twice.
    consumed: bool,
    /// Identity and rights established by the attestation. `issue_capability` reads these
    /// rather than accepting them from the caller, so a caller cannot mint a token for a
    /// different device or widen its rights.
    attested: Option<(AttestationClaim, Rights)>,
}

impl Handshake {
    /// Begin a handshake for a device that has just been attached.
    pub fn begin(now: u64) -> Result<Self, HandshakeError> {
        let mut nonce = [0u8; 32];
        sovereign_crypto::fill_random(&mut nonce)?;
        Ok(Self {
            state: HandshakeState::Challenged,
            nonce,
            issued_at: now,
            consumed: false,
            attested: None,
        })
    }

    /// Reconstruct a handshake from a challenge that was issued earlier.
    ///
    /// The nonce *is* the state, so a host that persisted nothing but the nonce can still
    /// validate the answer. `issued_at` must be the moment the challenge was minted, because
    /// the TTL is measured from it.
    pub fn from_challenge(nonce: [u8; 32], issued_at: u64) -> Result<Self, HandshakeError> {
        Ok(Self {
            state: HandshakeState::Challenged,
            nonce,
            issued_at,
            consumed: false,
            attested: None,
        })
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Verify the device's answer and narrow its rights.
    ///
    /// Returns the exact rights to grant. Note that the caller does not get to choose them:
    /// this is the only function that computes them, so there is no path by which a caller can
    /// hand itself wider rights than the policy allows.
    pub fn accept_attestation(
        &mut self,
        now: u64,
        cert: &DeviceCertificate,
        claim: &AttestationClaim,
        root: &HybridVerifyingKey,
    ) -> Result<Rights, HandshakeError> {
        if self.state != HandshakeState::Challenged || self.consumed {
            self.state = HandshakeState::Rejected;
            return Err(HandshakeError::ChallengeExpired);
        }

        if now < self.issued_at || now.saturating_sub(self.issued_at) > CHALLENGE_TTL_SECS {
            self.state = HandshakeState::Rejected;
            return Err(HandshakeError::ChallengeExpired);
        }

        // One answer per challenge, ever. Burn it before doing any expensive crypto so a
        // flood of bad answers cannot be used to grind our CPU.
        self.consumed = true;

        root.verify(
            labels::CAPABILITY,
            &cert.signing_payload(),
            &cert.root_signature,
        )
        .map_err(|_| {
            self.state = HandshakeState::Rejected;
            HandshakeError::UntrustedCertificate
        })?;

        if cert.device_id != claim.device_id || cert.device_key != claim.device_key {
            self.state = HandshakeState::Rejected;
            return Err(HandshakeError::CertificateMismatch);
        }

        let payload = attestation_payload(&self.nonce, &claim.device_id, claim.requested_rights);
        claim
            .device_key
            .verify(labels::ATTESTATION, &payload, &claim.signature)
            .map_err(|_| {
                self.state = HandshakeState::Rejected;
                HandshakeError::BadAttestation
            })?;

        let granted = claim
            .requested_rights
            .intersect(cert.max_rights)
            .intersect(PLUGIN_RIGHTS_CEILING);

        if granted.is_empty() {
            self.state = HandshakeState::Rejected;
            return Err(HandshakeError::NoRightsGranted);
        }

        self.state = HandshakeState::Attested;
        self.attested = Some((claim.clone(), granted));
        Ok(granted)
    }

    /// Mint the token the kernel will enforce. Requires a successful [`Self::accept_attestation`].
    ///
    /// The device id and the rights come from the attestation, not from the caller: there is no
    /// argument through which a caller could name a different device or request wider rights.
    /// `counter_base` is the only caller-supplied field, because the kernel decides where the
    /// replay window starts.
    pub fn issue_capability(
        &mut self,
        now: u64,
        counter_base: u64,
    ) -> Result<CapabilityToken, HandshakeError> {
        if self.state != HandshakeState::Attested {
            return Err(HandshakeError::IllegalTransition {
                from: self.state,
                to: HandshakeState::Active,
            });
        }
        let (claim, rights) = self
            .attested
            .as_ref()
            .ok_or(HandshakeError::IllegalTransition {
                from: self.state,
                to: HandshakeState::Active,
            })?;
        let expires_at = now
            .checked_add(DEFAULT_SESSION_SECS)
            .ok_or(HandshakeError::ClockError)?;
        let token = CapabilityToken {
            device_id: claim.device_id,
            rights: *rights,
            issued_at: now,
            expires_at,
            counter_base,
            handshake_nonce: self.nonce,
        };
        self.state = HandshakeState::Active;
        Ok(token)
    }

    /// Terminate the session. Idempotent.
    pub fn revoke(&mut self) {
        if self.state != HandshakeState::Rejected {
            self.state = HandshakeState::Revoked;
        }
    }

    pub fn reject(&mut self) {
        self.state = HandshakeState::Rejected;
    }
}

/// What the kernel needs in order to enforce a session without trusting the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub token: CapabilityToken,
    /// Root CA signature over `token.encode()`, so the kernel verifies the token itself
    /// instead of taking the bridge's word for it.
    pub root_signature: HybridSignature,
}

impl CapabilityGrant {
    pub fn encode(&self) -> Vec<u8> {
        let token = self.token.encode();
        let sig = self.root_signature.encode();
        let mut out = Vec::with_capacity(2 + token.len() + sig.len());
        out.extend_from_slice(&(token.len() as u16).to_be_bytes());
        out.extend_from_slice(&token);
        out.extend_from_slice(&sig);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, HandshakeError> {
        if buf.len() < 2 {
            return Err(HandshakeError::Crypto(CryptoError::Encoding));
        }
        let token_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if token_len != CapabilityToken::ENCODED_LEN || buf.len() < 2 + token_len {
            return Err(HandshakeError::Crypto(CryptoError::Encoding));
        }
        let token = CapabilityToken::decode(&buf[2..2 + token_len])
            .map_err(|_| HandshakeError::Crypto(CryptoError::Encoding))?;
        let root_signature = HybridSignature::decode(&buf[2 + token_len..])?;
        Ok(Self {
            token,
            root_signature,
        })
    }

    /// Verify the grant exactly as the kernel would: signature over the token bytes, then
    /// expiry against the kernel's own clock.
    pub fn verify(&self, root: &HybridVerifyingKey, now: u64) -> Result<(), HandshakeError> {
        root.verify(
            labels::CAPABILITY,
            &self.token.encode(),
            &self.root_signature,
        )?;
        if !self.token.is_valid_at(now) {
            return Err(HandshakeError::CapabilityExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_crypto::HybridSigningKey;

    /// Every known rights bit, used to prove the platform ceiling still wins over a
    /// permissive certificate.
    const ALL_RIGHTS: Rights = Rights::SENSOR_READ
        .union(Rights::TELEMETRY_WRITE)
        .union(Rights::NET_EGRESS)
        .union(Rights::CRYPTO_OP)
        .union(Rights::ADMIN);

    struct Fixture {
        root_sk: HybridSigningKey,
        root_vk: HybridVerifyingKey,
        device_sk: HybridSigningKey,
        cert: DeviceCertificate,
    }

    fn fixture(max_rights: Rights) -> Fixture {
        let root_sk = HybridSigningKey::generate().expect("entropy");
        let root_vk = root_sk.verifying_key();
        let device_sk = HybridSigningKey::generate().expect("entropy");
        let device_vk = device_sk.verifying_key();

        let mut cert = DeviceCertificate {
            device_id: [0x11; 16],
            device_key: device_vk,
            max_rights,
            root_signature: HybridSignature {
                ecdsa: [0u8; 96],
                mldsa: Vec::new(),
            },
        };
        cert.root_signature = root_sk
            .sign(labels::CAPABILITY, &cert.signing_payload())
            .expect("root sign");

        Fixture {
            root_sk,
            root_vk,
            device_sk,
            cert,
        }
    }

    fn claim(f: &Fixture, nonce: &[u8; 32], requested: Rights) -> AttestationClaim {
        let device_id = f.cert.device_id;
        let payload = attestation_payload(nonce, &device_id, requested);
        AttestationClaim {
            device_id,
            requested_rights: requested,
            device_key: f.device_sk.verifying_key(),
            signature: f
                .device_sk
                .sign(labels::ATTESTATION, &payload)
                .expect("device sign"),
        }
    }

    #[test]
    fn happy_path_grants_intersection() {
        let f = fixture(Rights::SENSOR_READ.union(Rights::TELEMETRY_WRITE));
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(
            &f,
            hs.nonce(),
            Rights::SENSOR_READ
                .union(Rights::TELEMETRY_WRITE)
                .union(Rights::ADMIN),
        );

        let granted = hs
            .accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");

        assert!(granted.contains(Rights::SENSOR_READ));
        assert!(granted.contains(Rights::TELEMETRY_WRITE));
        // ADMIN was requested but is not in the certificate.
        assert!(!granted.contains(Rights::ADMIN));
        assert_eq!(hs.state(), HandshakeState::Attested);

        let token = hs.issue_capability(1002, 1).expect("issue");
        assert_eq!(hs.state(), HandshakeState::Active);
        assert_eq!(token.rights, granted);
        assert_eq!(token.handshake_nonce, *hs.nonce());
    }

    #[test]
    fn admin_is_never_granted_to_a_plugin() {
        // Even a certificate that (wrongly) allows ADMIN cannot widen past the platform
        // ceiling: the grant is ADMIN+SENSOR_READ in, SENSOR_READ only out.
        let f = fixture(ALL_RIGHTS);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::ADMIN.union(Rights::SENSOR_READ));
        let granted = hs
            .accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");
        assert!(!granted.contains(Rights::ADMIN));
        assert_eq!(granted, Rights::SENSOR_READ);
    }

    #[test]
    fn a_device_that_asks_only_for_admin_gets_nothing() {
        // Asking for exactly the ungrantable right must fail closed, not silently grant
        // something else.
        let f = fixture(ALL_RIGHTS);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::ADMIN);
        assert_eq!(
            hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::NoRightsGranted
        );
        assert_eq!(hs.state(), HandshakeState::Rejected);
    }

    #[test]
    fn unsigned_certificate_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let mut cert = f.cert.clone();
        cert.max_rights = ALL_RIGHTS; // tamper after signing

        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1001, &cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::UntrustedCertificate
        );
        assert_eq!(hs.state(), HandshakeState::Rejected);
    }

    #[test]
    fn foreign_root_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let attacker_root = HybridSigningKey::generate()
            .expect("entropy")
            .verifying_key();

        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1001, &f.cert, &c, &attacker_root)
                .unwrap_err(),
            HandshakeError::UntrustedCertificate
        );
    }

    #[test]
    fn certificate_for_other_device_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let mut c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        c.device_id = [0x22; 16];
        assert_eq!(
            hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::CertificateMismatch
        );
    }

    #[test]
    fn signature_over_a_different_nonce_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let stale_nonce = [0xAB; 32];
        let c = claim(&f, &stale_nonce, Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::BadAttestation
        );
    }

    #[test]
    fn challenge_cannot_be_answered_twice() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let nonce = *hs.nonce();
        let c = claim(&f, &nonce, Rights::SENSOR_READ);
        hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("first answer");

        let c2 = claim(&f, &nonce, Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1002, &f.cert, &c2, &f.root_vk)
                .unwrap_err(),
            HandshakeError::ChallengeExpired
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1000 + CHALLENGE_TTL_SECS + 1, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::ChallengeExpired
        );
    }

    #[test]
    fn clock_going_backwards_is_rejected() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(999, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::ChallengeExpired
        );
    }

    #[test]
    fn empty_narrowing_is_refused() {
        let f = fixture(Rights::NONE);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        assert_eq!(
            hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::NoRightsGranted
        );
    }

    #[test]
    fn cannot_issue_capability_without_attestation() {
        let mut hs = Handshake::begin(1000).expect("begin");
        assert!(matches!(
            hs.issue_capability(1001, 1).unwrap_err(),
            HandshakeError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn grant_roundtrips_and_verifies() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");
        let token = hs.issue_capability(1002, 1).expect("issue");

        let grant = CapabilityGrant {
            root_signature: f
                .root_sk
                .sign(labels::CAPABILITY, &token.encode())
                .expect("sign"),
            token,
        };

        let enc = grant.encode();
        let decoded = CapabilityGrant::decode(&enc).expect("decode");
        assert_eq!(decoded, grant);
        decoded.verify(&f.root_vk, 1003).expect("kernel accepts");
    }

    #[test]
    fn tampered_grant_fails_verification() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");
        let token = hs.issue_capability(1002, 1).expect("issue");

        let mut grant = CapabilityGrant {
            root_signature: f
                .root_sk
                .sign(labels::CAPABILITY, &token.encode())
                .expect("sign"),
            token,
        };
        // Escalate rights after signing, the classic privilege-escalation attempt.
        grant.token.rights = ALL_RIGHTS;
        assert!(grant.verify(&f.root_vk, 1003).is_err());
    }

    #[test]
    fn expired_grant_fails_verification() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs.nonce(), Rights::SENSOR_READ);
        hs.accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");
        let token = hs.issue_capability(1002, 1).expect("issue");
        let grant = CapabilityGrant {
            root_signature: f
                .root_sk
                .sign(labels::CAPABILITY, &token.encode())
                .expect("sign"),
            token,
        };
        assert!(grant
            .verify(&f.root_vk, 1002 + DEFAULT_SESSION_SECS)
            .is_err());
    }

    #[test]
    fn from_challenge_reproduces_the_same_handshake() {
        let f = fixture(Rights::SENSOR_READ);
        let hs = Handshake::begin(1000).expect("begin");
        let nonce = *hs.nonce();

        // A stateless host that kept only the nonce and the issue time can still validate.
        let mut rebuilt = Handshake::from_challenge(nonce, 1000).expect("rebuild");
        let c = claim(&f, &nonce, Rights::SENSOR_READ);
        let granted = rebuilt
            .accept_attestation(1005, &f.cert, &c, &f.root_vk)
            .expect("attest");
        assert_eq!(granted, Rights::SENSOR_READ);
    }

    #[test]
    fn from_challenge_still_enforces_the_ttl() {
        let f = fixture(Rights::SENSOR_READ);
        let nonce = [0x5C; 32];
        let mut rebuilt = Handshake::from_challenge(nonce, 1000).expect("rebuild");
        let c = claim(&f, &nonce, Rights::SENSOR_READ);
        assert_eq!(
            rebuilt
                .accept_attestation(1000 + CHALLENGE_TTL_SECS + 1, &f.cert, &c, &f.root_vk)
                .unwrap_err(),
            HandshakeError::ChallengeExpired
        );
    }

    #[test]
    fn token_from_one_session_is_useless_in_another() {
        let f = fixture(Rights::SENSOR_READ);
        let mut hs_a = Handshake::begin(1000).expect("begin");
        let c = claim(&f, hs_a.nonce(), Rights::SENSOR_READ);
        hs_a.accept_attestation(1001, &f.cert, &c, &f.root_vk)
            .expect("attest");
        let token_a = hs_a.issue_capability(1002, 1).expect("issue");

        let hs_b = Handshake::begin(1003).expect("begin");
        assert_ne!(token_a.handshake_nonce, *hs_b.nonce());
    }
}
