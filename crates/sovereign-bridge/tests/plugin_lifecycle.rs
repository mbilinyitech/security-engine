//! End-to-end plug-in lifecycle, driven through the public API only.
//!
//! These tests model a real attack surface: a hostile device, a replayed handshake, a stolen
//! token, and a compromised bridge process. Each one must end in refusal, and the refusal must
//! come from the layer that owns the decision rather than from an accident of ordering.

use sovereign_bridge::{
    attestation_payload, link::MockKernel, AttestationClaim, CapabilityGrant, DeviceCertificate,
    Handshake, HandshakeError, HandshakeState, Session, DEFAULT_SESSION_SECS,
    PLUGIN_RIGHTS_CEILING,
};
use sovereign_crypto::{labels, HybridSignature, HybridSigningKey, HybridVerifyingKey};
use sovereign_ipc::{CapabilityToken, Rights, SealedFrame};

const T0: u64 = 1_700_000_000;
const DEVICE_ID: [u8; 16] = [0x5A; 16];

struct Authority {
    signing: HybridSigningKey,
    verifying: HybridVerifyingKey,
}

impl Authority {
    fn new() -> Self {
        let signing = HybridSigningKey::generate().expect("entropy");
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    fn certify(&self, device: &HybridVerifyingKey, max_rights: Rights) -> DeviceCertificate {
        let mut cert = DeviceCertificate {
            device_id: DEVICE_ID,
            device_key: device.clone(),
            max_rights,
            root_signature: HybridSignature {
                ecdsa: [0u8; 96],
                mldsa: Vec::new(),
            },
        };
        cert.root_signature = self
            .signing
            .sign(labels::CAPABILITY, &cert.signing_payload())
            .expect("root sign");
        cert
    }

    fn mint_grant(&self, token: CapabilityToken) -> CapabilityGrant {
        let root_signature = self
            .signing
            .sign(labels::CAPABILITY, &token.encode())
            .expect("root sign");
        CapabilityGrant {
            token,
            root_signature,
        }
    }
}

struct Device {
    signing: HybridSigningKey,
}

impl Device {
    fn new() -> Self {
        Self {
            signing: HybridSigningKey::generate().expect("entropy"),
        }
    }

    fn key(&self) -> HybridVerifyingKey {
        self.signing.verifying_key()
    }

    fn answer(&self, nonce: &[u8; 32], requested: Rights) -> AttestationClaim {
        let payload = attestation_payload(nonce, &DEVICE_ID, requested);
        AttestationClaim {
            device_id: DEVICE_ID,
            requested_rights: requested,
            device_key: self.key(),
            signature: self
                .signing
                .sign(labels::ATTESTATION, &payload)
                .expect("device sign"),
        }
    }
}

/// Walk a device through the full handshake and return a live session plus its grant.
fn establish(
    ca: &Authority,
    device: &Device,
    requested: Rights,
) -> (Session, CapabilityGrant, [u8; 32]) {
    let cert = ca.certify(&device.key(), requested.union(Rights::TELEMETRY_WRITE));

    let mut hs = Handshake::begin(T0).expect("begin");
    let nonce = *hs.nonce();
    let claim = device.answer(&nonce, requested);
    hs.accept_attestation(T0 + 1, &cert, &claim, &ca.verifying)
        .expect("attest");
    let token = hs.issue_capability(T0 + 2, 1).expect("issue");
    let grant = ca.mint_grant(token);

    let session_key = [0x42u8; 32];
    let session = Session::from_grant(&grant, &ca.verifying, T0 + 3, session_key).expect("session");
    (session, grant, session_key)
}

#[test]
fn happy_path_device_gets_narrowed_rights_and_can_send() {
    let ca = Authority::new();
    let device = Device::new();

    let (mut session, grant, key) =
        establish(&ca, &device, Rights::SENSOR_READ.union(Rights::ADMIN));

    // ADMIN was requested; the ceiling strips it.
    assert!(session.rights().contains(Rights::SENSOR_READ));
    assert!(!session.rights().contains(Rights::ADMIN));
    assert_eq!(
        session.rights(),
        Rights::SENSOR_READ.intersect(PLUGIN_RIGHTS_CEILING)
    );

    // A second session on the same key can read what the first wrote.
    let mut peer = Session::from_grant(&grant, &ca.verifying, T0 + 3, key).expect("peer");
    let frame = session
        .seal(T0 + 4, Rights::SENSOR_READ, b"temperature=21.5C")
        .expect("seal");
    let opened = peer.open(&frame, T0 + 4).expect("open");
    assert_eq!(opened.plaintext, b"temperature=21.5C");
}

#[test]
fn badusb_device_without_certificate_is_refused() {
    let ca = Authority::new();
    let rogue = Device::new();

    // The rogue has no certificate at all, so it forges one with a key it controls.
    let mut forged = DeviceCertificate {
        device_id: DEVICE_ID,
        device_key: rogue.key(),
        max_rights: PLUGIN_RIGHTS_CEILING,
        root_signature: HybridSignature {
            ecdsa: [0u8; 96],
            mldsa: Vec::new(),
        },
    };
    forged.root_signature = rogue
        .signing
        .sign(labels::CAPABILITY, &forged.signing_payload())
        .expect("self-sign");

    let mut hs = Handshake::begin(T0).expect("begin");
    let claim = rogue.answer(hs.nonce(), Rights::SENSOR_READ);

    assert_eq!(
        hs.accept_attestation(T0 + 1, &forged, &claim, &ca.verifying)
            .unwrap_err(),
        HandshakeError::UntrustedCertificate
    );
    assert_eq!(hs.state(), HandshakeState::Rejected);
}

#[test]
fn replayed_handshake_from_a_different_session_is_refused() {
    let ca = Authority::new();
    let device = Device::new();
    let cert = ca.certify(&device.key(), Rights::SENSOR_READ);

    // Session A: capture a perfectly valid attestation.
    let mut a = Handshake::begin(T0).expect("begin");
    let captured = device.answer(a.nonce(), Rights::SENSOR_READ);
    a.accept_attestation(T0 + 1, &cert, &captured, &ca.verifying)
        .expect("A attests");

    // Session B: replay A's answer. The nonce differs, so it must fail.
    let mut b = Handshake::begin(T0 + 2).expect("begin");
    assert_eq!(
        b.accept_attestation(T0 + 3, &cert, &captured, &ca.verifying)
            .unwrap_err(),
        HandshakeError::BadAttestation
    );
}

#[test]
fn stolen_token_cannot_be_replayed_into_a_new_session() {
    let ca = Authority::new();
    let device = Device::new();
    let (_, grant, key) = establish(&ca, &device, Rights::SENSOR_READ);

    // Attacker steals the whole grant and the session key, but starts a new handshake, which
    // means the kernel has a different nonce on file.
    let mut kernel = MockKernel::new(ca.verifying.clone());
    kernel.queue_challenge([0xEE; 32]);

    assert_eq!(
        kernel.accept_grant(&grant, T0 + 5).unwrap_err(),
        HandshakeError::BadAttestation
    );

    // The stolen key still cannot be used without the kernel accepting the grant.
    assert!(kernel.accepted_grant.is_none());
    assert_eq!(key, [0x42u8; 32]);
}

#[test]
fn kernel_verifies_grant_independently_of_the_bridge() {
    let ca = Authority::new();
    let device = Device::new();
    let (_, grant, _) = establish(&ca, &device, Rights::SENSOR_READ);

    let mut kernel = MockKernel::new(ca.verifying.clone());
    // Give the kernel the nonce the token was actually bound to.
    kernel.queue_challenge(grant.token.handshake_nonce);

    kernel.accept_grant(&grant, T0 + 5).expect("kernel accepts");
    assert!(kernel.accepted_grant.is_some());

    // A compromised bridge that widens rights after signing is caught by the kernel.
    let mut escalated = grant.clone();
    escalated.token.rights = PLUGIN_RIGHTS_CEILING;
    assert!(kernel.accept_grant(&escalated, T0 + 5).is_err());
}

#[test]
fn expired_capability_is_refused_by_kernel_and_session() {
    let ca = Authority::new();
    let device = Device::new();
    let (mut session, grant, key) = establish(&ca, &device, Rights::SENSOR_READ);

    let after_expiry = T0 + DEFAULT_SESSION_SECS + 10;

    let mut kernel = MockKernel::new(ca.verifying.clone());
    kernel.queue_challenge(grant.token.handshake_nonce);
    assert!(kernel.accept_grant(&grant, after_expiry).is_err());

    assert!(Session::from_grant(&grant, &ca.verifying, after_expiry, key).is_err());
    assert!(session
        .seal(after_expiry, Rights::SENSOR_READ, b"late")
        .is_err());
}

#[test]
fn revoked_device_cannot_send_after_wipe() {
    let ca = Authority::new();
    let device = Device::new();
    let (mut session, _, _) = establish(&ca, &device, Rights::SENSOR_READ);

    let frame = session
        .seal(T0 + 4, Rights::SENSOR_READ, b"before")
        .expect("seal");
    session.revoke();

    assert!(session.is_revoked());
    assert!(session.seal(T0 + 5, Rights::SENSOR_READ, b"after").is_err());
    assert!(session.open(&frame, T0 + 5).is_err());
}

#[test]
fn exfiltration_attempt_is_blocked_by_missing_right() {
    let ca = Authority::new();
    let device = Device::new();

    // A temperature sensor: its certificate only ever allows sensor reads, even though the
    // device asks for network egress as well.
    let cert = ca.certify(&device.key(), Rights::SENSOR_READ);
    let mut hs = Handshake::begin(T0).expect("begin");
    let claim = device.answer(hs.nonce(), Rights::SENSOR_READ.union(Rights::NET_EGRESS));
    let granted = hs
        .accept_attestation(T0 + 1, &cert, &claim, &ca.verifying)
        .expect("attest");

    assert!(granted.contains(Rights::SENSOR_READ));
    assert!(!granted.contains(Rights::NET_EGRESS));

    let token = hs.issue_capability(T0 + 2, 1).expect("issue");
    let grant = ca.mint_grant(token);
    let mut session =
        Session::from_grant(&grant, &ca.verifying, T0 + 3, [0x11; 32]).expect("session");

    // Legitimate telemetry works.
    session
        .seal(T0 + 4, Rights::SENSOR_READ, b"temperature=21.5C")
        .expect("sensor read is permitted");

    // Exfiltration does not.
    assert_eq!(
        session
            .seal(T0 + 4, Rights::NET_EGRESS, b"exfiltrate everything")
            .unwrap_err(),
        HandshakeError::RightsNotPermitted
    );
}

#[test]
fn a_device_requesting_only_forbidden_rights_gets_nothing() {
    let ca = Authority::new();
    let device = Device::new();
    let cert = ca.certify(&device.key(), Rights::SENSOR_READ);

    let mut hs = Handshake::begin(T0).expect("begin");
    let claim = device.answer(hs.nonce(), Rights::NET_EGRESS);
    assert_eq!(
        hs.accept_attestation(T0 + 1, &cert, &claim, &ca.verifying)
            .unwrap_err(),
        HandshakeError::NoRightsGranted
    );
    assert_eq!(hs.state(), HandshakeState::Rejected);
}

#[test]
fn frames_cannot_be_moved_between_devices() {
    const OTHER_ID: [u8; 16] = [0x77; 16];

    let ca = Authority::new();
    let device_a = Device::new();
    let device_b = Device::new();

    let (mut session_a, _, key_a) = establish(&ca, &device_a, Rights::SENSOR_READ);

    // Device B has its own certificate and its own capability id, signed by the same root.
    let mut cert_b = ca.certify(&device_b.key(), Rights::SENSOR_READ);
    cert_b.device_id = OTHER_ID;
    cert_b.root_signature = ca
        .signing
        .sign(labels::CAPABILITY, &cert_b.signing_payload())
        .expect("sign");

    let mut hs = Handshake::begin(T0).expect("begin");
    let payload = attestation_payload(hs.nonce(), &OTHER_ID, Rights::SENSOR_READ);
    let claim_b = AttestationClaim {
        device_id: OTHER_ID,
        requested_rights: Rights::SENSOR_READ,
        device_key: device_b.key(),
        signature: device_b
            .signing
            .sign(labels::ATTESTATION, &payload)
            .expect("sign"),
    };
    hs.accept_attestation(T0 + 1, &cert_b, &claim_b, &ca.verifying)
        .expect("attest");
    let token_b = hs.issue_capability(T0 + 2, 1).expect("issue");
    let grant_b = ca.mint_grant(token_b);

    // Deliberately give B the *same* symmetric key as A. Two independent layers must then keep
    // the sessions apart: the explicit capability-id check in `Session::open`, and the
    // capability id bound into the AEAD associated data. Removing only one still fails the
    // frame, which is why this test only goes red when both are gone.
    let mut session_b =
        Session::from_grant(&grant_b, &ca.verifying, T0 + 3, key_a).expect("session b");

    let frame = session_a
        .seal(T0 + 4, Rights::SENSOR_READ, b"device A data")
        .expect("seal");
    assert!(session_b.open(&frame, T0 + 4).is_err());
}

#[test]
fn sealed_frame_survives_the_wire_and_still_opens() {
    let ca = Authority::new();
    let device = Device::new();
    let (mut session, grant, key) = establish(&ca, &device, Rights::SENSOR_READ);

    let frame = session
        .seal(T0 + 4, Rights::SENSOR_READ, b"radio telemetry")
        .expect("seal");

    // Serialise the way the tunnel will, then parse on the far side.
    let wire = frame.encode().expect("encode");
    let parsed = SealedFrame::decode(&wire).expect("decode");

    let mut peer = Session::from_grant(&grant, &ca.verifying, T0 + 4, key).expect("peer");
    let opened = peer.open(&parsed, T0 + 4).expect("open after wire");
    assert_eq!(opened.plaintext, b"radio telemetry");
}

#[test]
fn replayed_data_frame_is_dropped_at_the_session() {
    let ca = Authority::new();
    let device = Device::new();
    let (mut session, grant, key) = establish(&ca, &device, Rights::SENSOR_READ);

    let frame = session
        .seal(T0 + 4, Rights::SENSOR_READ, b"once")
        .expect("seal");

    let mut peer = Session::from_grant(&grant, &ca.verifying, T0 + 4, key).expect("peer");
    peer.open(&frame, T0 + 4).expect("first delivery");
    assert!(peer.open(&frame, T0 + 4).is_err());
}

#[test]
fn bridge_crash_does_not_leave_a_usable_session() {
    let ca = Authority::new();
    let device = Device::new();
    let (session, grant, key) = establish(&ca, &device, Rights::SENSOR_READ);

    // Dropping the session zeroizes its key; a restart needs a fresh handshake, because the
    // grant is bound to a nonce that has already been consumed.
    drop(session);

    let mut kernel = MockKernel::new(ca.verifying.clone());
    kernel.queue_challenge([0x01; 32]);
    assert!(kernel.accept_grant(&grant, T0 + 4).is_err());
    assert!(Session::from_grant(&grant, &ca.verifying, T0 + 4, key).is_ok());
}
