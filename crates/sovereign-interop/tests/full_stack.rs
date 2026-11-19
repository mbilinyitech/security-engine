//! One device, end to end, through every layer.
//!
//! Each crate in this workspace has its own tests, but a system is not the sum of its parts. This
//! test drives a single device through the whole stack in one sequence and asserts the properties
//! that only exist *between* layers:
//!
//! 1. a device completes the plug-in handshake and receives narrowed rights;
//! 2. the capability it receives is signed by the root authority and verifies independently;
//! 3. the session seals a payload, and the payload travels as a tunnel datagram;
//! 4. the receiving side opens it and gets the original bytes back;
//! 5. a replayed datagram is refused by the tunnel's replay window;
//! 6. every step above left a verifiable entry in the audit ledger;
//! 7. the verification swarm agrees the capability is good, and reports disagreement when one
//!    verifier is fed a different view of the same artifact;
//! 8. a capability-gated agent script runs under the rights the device actually received, and is
//!    refused when those rights are absent;
//! 9. the OS-agnostic interop handshake and the cryptographic bridge handshake reach the same
//!    verdict about the same device.
//!
//! The point is not that each piece works in isolation — their own tests cover that. It is that
//! the pieces compose without any layer quietly widening what the layer below it allowed.

use std::io::Write as _;

use sovereign_agent::{parse_manifest, Registry};
use sovereign_bridge::{
    attestation_payload, AttestationClaim, CapabilityGrant, DeviceCertificate, Handshake,
    HandshakeState, Session, PLUGIN_RIGHTS_CEILING,
};
use sovereign_crypto::{labels, HybridSignature, HybridSigningKey, HybridVerifyingKey};
use sovereign_interop::{encode_hello_reply, handshake as interop_handshake, LinuxChardev};
use sovereign_ipc::{CapabilityToken, Frame, OpCode, Rights};
use sovereign_ledger::Ledger;
use sovereign_swarm::{Artifact, SignedSwarm, Swarm, SwarmError, Verdict};
use sovereign_tunnel::{Datagram, PeerReplay};

const T0: u64 = 1_700_000_000;
const DEVICE_ID: [u8; 16] = [0x5A; 16];
/// The session key the hybrid KEM would have produced. Fixed here because the KEM exchange is
/// tested in `sovereign-crypto`; this test is about what happens to the key afterwards.
const SESSION_KEY: [u8; 32] = [0x33; 32];

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

/// Run the full handshake and return the session plus the grant that authorised it.
fn enrol(
    authority: &Authority,
    device: &HybridSigningKey,
    requested: Rights,
) -> (Session, CapabilityGrant) {
    let cert = authority.certify(&device.verifying_key(), PLUGIN_RIGHTS_CEILING);

    let mut hs = Handshake::begin(T0).expect("challenge");
    let nonce = *hs.nonce();
    let claim = AttestationClaim {
        device_id: DEVICE_ID,
        requested_rights: requested,
        device_key: device.verifying_key(),
        signature: device
            .sign(
                labels::ATTESTATION,
                &attestation_payload(&nonce, &DEVICE_ID, requested),
            )
            .expect("device sign"),
    };

    let granted = hs
        .accept_attestation(T0 + 1, &cert, &claim, &authority.verifying)
        .expect("attestation accepted");
    assert_eq!(hs.state(), HandshakeState::Attested);

    let token = hs.issue_capability(T0 + 2, 1).expect("capability");
    assert_eq!(
        token.rights, granted,
        "token carries exactly the narrowed rights"
    );

    let grant = authority.mint_grant(token);
    let session =
        Session::from_grant(&grant, &authority.verifying, T0 + 3, SESSION_KEY).expect("session");
    (session, grant)
}

#[test]
fn a_device_travels_the_whole_stack_and_every_layer_agrees() {
    let authority = Authority::new();
    let device = HybridSigningKey::generate().expect("entropy");
    let mut ledger = Ledger::new();

    // --- 1. Enrolment. The device asks for ADMIN, which no plug-in may ever hold. ---------
    //
    // Requesting only rights that are already inside the ceiling would make the narrowing
    // invisible: a mutant that skipped the intersection would grant the same set and every
    // assertion would still pass. Asking for something outside the ceiling is what makes the
    // check observable, so this is the interesting case, not an unrealistic one.
    let requested = Rights::SENSOR_READ
        .union(Rights::TELEMETRY_WRITE)
        .union(Rights::ADMIN);
    let (mut session, grant) = enrol(&authority, &device, requested);

    ledger
        .append(T0 + 4, "plugin.enrolled", &DEVICE_ID)
        .expect("audit");

    assert_eq!(session.rights(), grant.token.rights);
    assert!(
        !session.rights().contains(Rights::ADMIN),
        "a plug-in never receives admin, however loudly it asks"
    );
    assert_eq!(
        session.rights(),
        Rights::SENSOR_READ.union(Rights::TELEMETRY_WRITE),
        "the grant is exactly the request intersected with policy"
    );

    // --- 2. The capability verifies independently of the bridge that carried it. -----------
    grant
        .verify(&authority.verifying, T0 + 5)
        .expect("kernel-side verification");

    // --- 3. Seal a payload under the session's own rights. --------------------------------
    let plaintext = b"thermal: 21.4C";
    let sealed = session
        .seal(T0 + 6, Rights::SENSOR_READ, plaintext)
        .expect("seal");
    ledger
        .append(T0 + 6, "session.sealed", &sealed.counter.to_be_bytes())
        .expect("audit");

    // --- 4. Carry it as a tunnel datagram. -----------------------------------------------
    let datagram = Datagram::seal(&sealed).expect("datagram");
    let wire = datagram.encode().expect("encode");

    // --- 5. The receiver opens it, and gets the original bytes. --------------------------
    let received = Datagram::decode(&wire).expect("decode");
    let mut receiver_session =
        Session::from_grant(&grant, &authority.verifying, T0 + 7, SESSION_KEY)
            .expect("receiver session");
    let opened = receiver_session
        .open(received.frame(), T0 + 8)
        .expect("open");
    assert_eq!(opened.plaintext, plaintext);
    ledger
        .append(
            T0 + 8,
            "session.opened",
            &opened.plaintext.len().to_be_bytes(),
        )
        .expect("audit");

    // --- 6. A replayed datagram is refused by the tunnel, before any crypto. -------------
    let mut replay = PeerReplay::new();
    replay.accept(received.counter()).expect("first accepted");
    assert!(
        replay.accept(received.counter()).is_err(),
        "the same counter must not pass twice"
    );
    ledger
        .append(
            T0 + 9,
            "tunnel.replay_refused",
            &received.counter().to_be_bytes(),
        )
        .expect("audit");

    // --- 7. The verification swarm agrees, using the real hybrid signature. --------------
    let token_bytes = grant.token.encode();
    let artifact = Artifact {
        domain: labels::CAPABILITY,
        payload: &token_bytes,
        claimed_rights: grant.token.rights,
        ceiling: PLUGIN_RIGHTS_CEILING,
        now: T0 + 10,
        not_before: Some(grant.token.issued_at),
        expected_digest: Some(sovereign_swarm::digest_of(labels::CAPABILITY, &token_bytes)),
    };
    let signed_swarm = SignedSwarm::new(&authority.verifying, &grant.root_signature);
    let outcomes = signed_swarm.evaluate(&artifact).expect("swarm accepts");
    assert!(outcomes.iter().all(|o| o.verdict == Verdict::Accept));
    ledger
        .append(T0 + 10, "swarm.accept", &DEVICE_ID)
        .expect("audit");

    // --- 8. A capability-gated agent script runs under the device's real rights. --------
    let manifest = parse_manifest(
        "name = read-thermal\n\
         kind = script\n\
         requires = SENSOR_READ\n\
         step = read_sensor\n",
    )
    .expect("manifest");

    let mut registry = Registry::new(&mut ledger);
    registry.register("read_sensor", |_args| Ok(()));
    let report = registry
        .run(&manifest, session.rights(), T0 + 11)
        .expect("agent run");
    assert_eq!(report.steps_ok, 1);

    // The same script under a device that lacks the right is refused, and the refusal is logged.
    let mut ledger2 = Ledger::new();
    let mut registry2 = Registry::new(&mut ledger2);
    registry2.register("read_sensor", |_args| Ok(()));
    let denied = registry2.run(&manifest, Rights::TELEMETRY_WRITE, T0 + 12);
    assert!(denied.is_err(), "missing right must refuse the run");
    assert_eq!(
        ledger2.entries().last().expect("entry").kind,
        "agent.run.denied"
    );

    // --- 9. Everything above is in one intact chain. -------------------------------------
    let count = ledger.len();
    assert!(count >= 7, "expected the full trail, got {count}");
    assert_eq!(ledger.verify(None, None), Ok(count));

    // A signed checkpoint proves the head, so truncation by a later attacker is detectable.
    let checkpoint = ledger.checkpoint(&authority.signing).expect("checkpoint");
    assert_eq!(checkpoint.head, ledger.head());
}

#[test]
fn a_device_without_a_root_signature_never_reaches_a_session() {
    let authority = Authority::new();
    let device = HybridSigningKey::generate().expect("entropy");

    // A certificate whose signature was made by the device itself rather than the root.
    let mut forged = DeviceCertificate {
        device_id: DEVICE_ID,
        device_key: device.verifying_key(),
        max_rights: PLUGIN_RIGHTS_CEILING,
        root_signature: HybridSignature {
            ecdsa: [0u8; 96],
            mldsa: Vec::new(),
        },
    };
    forged.root_signature = device
        .sign(labels::CAPABILITY, &forged.signing_payload())
        .expect("self sign");

    let mut hs = Handshake::begin(T0).expect("challenge");
    let nonce = *hs.nonce();
    let claim = AttestationClaim {
        device_id: DEVICE_ID,
        requested_rights: Rights::SENSOR_READ,
        device_key: device.verifying_key(),
        signature: device
            .sign(
                labels::ATTESTATION,
                &attestation_payload(&nonce, &DEVICE_ID, Rights::SENSOR_READ),
            )
            .expect("sign"),
    };

    assert!(hs
        .accept_attestation(T0 + 1, &forged, &claim, &authority.verifying)
        .is_err());
    assert_eq!(hs.state(), HandshakeState::Rejected);
    // And no capability can be minted from a rejected handshake.
    assert!(hs.issue_capability(T0 + 2, 1).is_err());
}

#[test]
fn the_swarm_reports_disagreement_when_one_verifier_is_told_a_different_story() {
    // This is the property the swarm exists for. Two corroborators answer the same question;
    // one is given a stale view. The result must be Disagreement, not a rejection, because
    // disagreement is the signal that something is wrong with the *checking*, not the artifact.
    let authority = Authority::new();
    let device = HybridSigningKey::generate().expect("entropy");
    let (_, grant) = enrol(&authority, &device, Rights::SENSOR_READ);
    let token_bytes = grant.token.encode();

    let mut swarm = Swarm::new();
    // Honest verifier: checks the digest of what it was given.
    swarm.corroborate_with("digest", sovereign_swarm::check_digest);
    // Compromised verifier: believes the artifact is fine no matter what.
    swarm.corroborate_with("rubber-stamp", |_| Verdict::Accept);

    let good = Artifact {
        domain: labels::CAPABILITY,
        payload: &token_bytes,
        claimed_rights: grant.token.rights,
        ceiling: PLUGIN_RIGHTS_CEILING,
        now: T0 + 10,
        not_before: Some(grant.token.issued_at),
        expected_digest: Some(sovereign_swarm::digest_of(labels::CAPABILITY, &token_bytes)),
    };
    assert!(
        swarm.corroborate(&good).is_ok(),
        "both agree on a good token"
    );

    // Now the caller's expectation is for different bytes than were delivered.
    let tampered = Artifact {
        expected_digest: Some([0u8; 32]),
        ..good.clone()
    };
    let e = swarm.corroborate(&tampered).unwrap_err();
    assert!(matches!(e, SwarmError::Disagreement { .. }), "got {e:?}");
    assert!(e.to_string().contains("DISAGREEMENT"));
}

#[test]
fn the_os_agnostic_handshake_and_the_sovereign_handshake_reach_the_same_verdict() {
    // Two handshakes exist in this workspace: the interop one, which establishes *what a device
    // is* across operating systems, and the bridge one, which establishes *what it may do*.
    // They must agree that a good device is a good device, or a device would be trusted on one
    // path and refused on the other.
    let authority = Authority::new();
    let device = HybridSigningKey::generate().expect("entropy");

    // Interop path: model name and requested rights over a real file descriptor.
    let (mut peer, fd) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let mut dev = LinuxChardev::new(fd, "/dev/sovereign0");
    let reply = Frame::new(
        OpCode::Hello,
        encode_hello_reply("thermal-01", Rights::SENSOR_READ).expect("encode"),
    )
    .expect("frame");
    peer.write_all(&reply.encode()).expect("write");

    let interop_session = interop_handshake(&mut dev, PLUGIN_RIGHTS_CEILING).expect("interop");
    assert_eq!(interop_session.info.model, "thermal-01");
    assert_eq!(interop_session.granted_rights, Rights::SENSOR_READ);

    // Bridge path: full cryptographic attestation.
    let (bridge_session, _) = enrol(&authority, &device, Rights::SENSOR_READ);

    assert_eq!(
        interop_session.granted_rights,
        bridge_session.rights(),
        "both paths must grant the same rights for the same request"
    );
}
