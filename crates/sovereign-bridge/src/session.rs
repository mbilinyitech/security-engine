//! The bridge session: owns the keys, the counter, and the right to emit frames.
//!
//! A [`Session`] can only exist after a successful handshake, and it can only be created by
//! [`Session::from_grant`], which re-verifies the grant. That means there is exactly one place
//! in the codebase where "this device may send data" becomes true, and it is a place that
//! fails closed.
//!
//! The session hands out [`SealedFrame`]s. It never touches the network itself — that is the
//! stealth tunnel's job (layer 6). Keeping the two apart means a bug in the tunnel cannot
//! weaken the sealing, and a bug here cannot leak plaintext onto the wire.

use sovereign_crypto::{
    open as aead_open, seal as aead_seal, CryptoError, HybridVerifyingKey, ReplayWindow, SealingKey,
};
use sovereign_ipc::{CapabilityToken, Rights, SealedFrame};

use crate::handshake::{CapabilityGrant, HandshakeError};

/// Result of trying to open an inbound sealed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    pub counter: u64,
    pub plaintext: Vec<u8>,
}

/// An established, capability-bound session.
pub struct Session {
    token: CapabilityToken,
    key: SealingKey,
    /// Key for the immediately preceding epoch, kept so that a frame reordered across one epoch
    /// boundary still opens. Dropped as soon as the session moves a second epoch forward.
    prev_key: Option<SealingKey>,
    /// Next counter to stamp on an outbound frame. Monotonic and never reused.
    next_counter: u64,
    /// Replay protection for inbound frames from the peer.
    replay: ReplayWindow,
    epoch: u32,
    /// Frames sealed in the current epoch. Only consulted when auto-ratcheting is enabled.
    frames_in_epoch: u64,
    /// Ratchet automatically after this many sealed frames. `None` means the caller drives
    /// rotation by hand.
    ratchet_after: Option<u64>,
    revoked: bool,
}

/// How far ahead of its own epoch a session will walk the key chain to open a frame.
///
/// The epoch is authenticated as associated data, so a forged frame cannot *commit* an advance
/// (see `open`), but the chain walk still costs one HKDF per epoch and must be bounded. Eight
/// epochs is generous for packet loss and far too small to be a CPU lever.
const MAX_EPOCH_SKIP: u32 = 8;

/// The deterministic mix-in for an epoch.
///
/// Both peers derive it from the epoch number alone, so no coordination is needed to stay in
/// step. It is public on purpose: a symmetric ratchet gets its forward secrecy from the one-way
/// function, not from this value being secret. Post-compromise security needs [`rekey`] and a
/// real key exchange.
fn epoch_mix(epoch: u32) -> [u8; 32] {
    let mut m = [0u8; 32];
    m[..4].copy_from_slice(&epoch.to_be_bytes());
    m
}

impl Session {
    /// Build a session from a grant, verifying it first.
    ///
    /// `session_key` is the raw output of the hybrid KEM run during the handshake. It is not
    /// used as the AEAD key directly: it is bound to this device id and this handshake nonce
    /// first, so the same shared secret produces a different key in every session. Possessing a
    /// token is therefore not enough to open traffic, and a key captured from one session cannot
    /// be transplanted into another.
    pub fn from_grant(
        grant: &CapabilityGrant,
        root: &HybridVerifyingKey,
        now: u64,
        session_key: [u8; 32],
    ) -> Result<Self, HandshakeError> {
        grant.verify(root, now)?;
        if grant.token.rights.is_empty() {
            return Err(HandshakeError::NoRightsGranted);
        }
        Ok(Self {
            next_counter: grant.token.counter_base,
            token: grant.token.clone(),
            key: sovereign_crypto::session_key(
                &session_key,
                &grant.token.device_id,
                &grant.token.handshake_nonce,
            ),
            prev_key: None,
            replay: ReplayWindow::new(),
            epoch: 0,
            frames_in_epoch: 0,
            ratchet_after: None,
            revoked: false,
        })
    }

    /// Ratchet automatically every `frames` sealed frames.
    ///
    /// Without this the session only rotates when the caller says so, and a caller that never
    /// says so gets no forward secrecy at all. Both peers must be configured with the same
    /// value: the epoch is part of the authenticated header, so a peer that ratchets on a
    /// different schedule simply falls behind and catches up when it sees the higher epoch.
    ///
    /// `frames` is clamped to at least 1. Zero would mean "ratchet on every frame", which is
    /// legal but pointless — the counter already prevents reuse within an epoch.
    pub fn with_auto_ratchet(mut self, frames: u64) -> Self {
        self.ratchet_after = Some(frames.max(1));
        self
    }

    pub fn capability(&self) -> &CapabilityToken {
        &self.token
    }

    pub fn rights(&self) -> Rights {
        self.token.rights
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Stop using this session. Drops the key material when the struct is dropped.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Advance to the next epoch, deriving the new key from the current one.
    ///
    /// `mix_in` is fresh entropy from a new key exchange. It is mixed into the derivation rather
    /// than used as the key directly, so a caller cannot install an arbitrary key while claiming
    /// a rotation, and the new key always depends on the old one — which is what makes the old
    /// key worth destroying.
    ///
    /// The counter keeps increasing so a peer cannot use the rotation to replay old frames under
    /// a fresh epoch.
    pub fn rotate(&mut self, mix_in: [u8; 32]) {
        let next_epoch = self.epoch.wrapping_add(1);
        // Keep exactly one epoch of history so a frame that was in flight across the boundary
        // still opens. Keeping more would mean keeping old keys, which is the thing forward
        // secrecy is supposed to prevent; keeping none would turn ordinary reordering into
        // data loss.
        let next = sovereign_crypto::ratchet(&self.key, &mix_in, next_epoch);
        let old = core::mem::replace(&mut self.key, next);
        self.prev_key = Some(old);
        self.epoch = next_epoch;
        self.frames_in_epoch = 0;
    }

    /// Advance the epoch using the deterministic per-epoch mix-in.
    ///
    /// Used by the automatic ratchet. A caller that has a fresh KEM secret should call
    /// [`Session::rekey`] instead, which additionally recovers from a past key compromise.
    fn ratchet_epoch(&mut self) {
        self.rotate(epoch_mix(self.epoch.wrapping_add(1)));
    }

    /// Advance the epoch by mixing in a fresh shared secret from a new KEM exchange.
    ///
    /// Unlike [`Session::rotate`], an attacker who captured the current key cannot compute the
    /// result, because it depends on a secret they do not have. This is the only operation here
    /// that recovers after a compromise. The peer must perform the same exchange and pass the
    /// same secret.
    pub fn rekey(&mut self, shared: [u8; 32]) {
        let next_epoch = self.epoch.wrapping_add(1);
        let next = sovereign_crypto::rekey(&self.key, &shared, next_epoch);
        let old = core::mem::replace(&mut self.key, next);
        self.prev_key = Some(old);
        self.epoch = next_epoch;
        self.frames_in_epoch = 0;
    }

    /// Seal `plaintext` into a frame, enforcing the capability first.
    ///
    /// Refuses if revoked, if the capability expired, or if the required right is absent. The
    /// check happens here rather than at the call site so there is no way to emit a frame
    /// without it.
    pub fn seal(
        &mut self,
        now: u64,
        required: Rights,
        plaintext: &[u8],
    ) -> Result<SealedFrame, HandshakeError> {
        if self.revoked {
            return Err(HandshakeError::IllegalTransition {
                from: crate::handshake::HandshakeState::Revoked,
                to: crate::handshake::HandshakeState::Active,
            });
        }
        if !self.token.is_valid_at(now) {
            self.revoked = true;
            return Err(HandshakeError::CapabilityExpired);
        }
        if !self.token.rights.contains(required) {
            return Err(HandshakeError::RightsNotPermitted);
        }

        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(HandshakeError::ClockError)?;

        // Build the header first: it is the AEAD associated data, so the counter, epoch and
        // nonce are authenticated even though they travel in the clear.
        let mut frame = SealedFrame {
            capability_id: self.token.device_id,
            counter,
            epoch: self.epoch,
            nonce: [0u8; 24],
            ciphertext: Vec::new(),
        };
        let (nonce, ct) = aead_seal(&self.key, &frame.associated_data(), plaintext)?;
        frame.nonce = nonce;
        frame.ciphertext = ct;

        // Ratchet only after the frame is built, so it carries the epoch it was sealed under.
        self.frames_in_epoch = self.frames_in_epoch.saturating_add(1);
        if let Some(limit) = self.ratchet_after {
            if self.frames_in_epoch >= limit {
                self.ratchet_epoch();
            }
        }
        Ok(frame)
    }

    /// Open an inbound frame: verify the capability id, the epoch, the counter, and the tag.
    ///
    /// The replay window is only advanced *after* authentication succeeds, so an attacker
    /// cannot burn counters by sending garbage.
    pub fn open(&mut self, frame: &SealedFrame, now: u64) -> Result<OpenedFrame, CryptoError> {
        if self.revoked || !self.token.is_valid_at(now) {
            return Err(CryptoError::Verification);
        }
        if frame.capability_id != self.token.device_id {
            return Err(CryptoError::Verification);
        }
        // Same epoch: the common case.
        if frame.epoch == self.epoch {
            let plaintext = aead_open(
                &self.key,
                &frame.associated_data(),
                &frame.nonce,
                &frame.ciphertext,
            )?;
            self.replay.accept(frame.counter)?;
            return Ok(OpenedFrame {
                counter: frame.counter,
                plaintext,
            });
        }

        // Exactly one epoch behind: the peer ratcheted while this frame was in flight. Only the
        // immediately previous key is retained, so anything older is refused outright.
        if frame.epoch.checked_add(1) == Some(self.epoch) {
            let prev = self.prev_key.as_ref().ok_or(CryptoError::Verification)?;
            let plaintext = aead_open(
                prev,
                &frame.associated_data(),
                &frame.nonce,
                &frame.ciphertext,
            )?;
            self.replay.accept(frame.counter)?;
            return Ok(OpenedFrame {
                counter: frame.counter,
                plaintext,
            });
        }

        // Ahead: the peer ratcheted and we have not caught up. Walk the chain without touching
        // our state first. Committing before authentication would let anyone who can send a UDP
        // packet with a large epoch number advance our epoch arbitrarily, destroying the keys we
        // still need for genuine in-flight frames — a denial of service dressed as progress.
        if frame.epoch > self.epoch {
            let skip = frame.epoch - self.epoch;
            if skip > MAX_EPOCH_SKIP {
                return Err(CryptoError::Verification);
            }
            let mut candidate = self.key.clone();
            for e in (self.epoch + 1)..=frame.epoch {
                candidate = sovereign_crypto::ratchet(&candidate, &epoch_mix(e), e);
            }
            let plaintext = aead_open(
                &candidate,
                &frame.associated_data(),
                &frame.nonce,
                &frame.ciphertext,
            )?;

            // Authenticated, so the sender really is our peer and really did ratchet.
            let old = core::mem::replace(&mut self.key, candidate);
            self.prev_key = Some(old);
            self.epoch = frame.epoch;
            self.frames_in_epoch = 0;
            self.replay.accept(frame.counter)?;
            return Ok(OpenedFrame {
                counter: frame.counter,
                plaintext,
            });
        }

        Err(CryptoError::Verification)
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("device_id", &hex::encode(self.token.device_id))
            .field("rights", &self.token.rights.bits())
            .field("epoch", &self.epoch)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_crypto::{labels, HybridSigningKey};
    use sovereign_ipc::CapabilityToken;

    const ROOT_NOW: u64 = 1_000;

    struct Env {
        root_sk: HybridSigningKey,
        root_vk: HybridVerifyingKey,
        grant: CapabilityGrant,
        key: [u8; 32],
    }

    fn env(rights: Rights) -> Env {
        env_with_nonce(rights, [0x44; 32])
    }

    fn env_with_nonce(rights: Rights, handshake_nonce: [u8; 32]) -> Env {
        let root_sk = HybridSigningKey::generate().expect("entropy");
        let root_vk = root_sk.verifying_key();
        let token = CapabilityToken {
            device_id: [0x33; 16],
            rights,
            issued_at: ROOT_NOW,
            expires_at: ROOT_NOW + 600,
            counter_base: 1,
            handshake_nonce,
        };
        let grant = CapabilityGrant {
            root_signature: root_sk
                .sign(labels::CAPABILITY, &token.encode())
                .expect("sign"),
            token,
        };
        Env {
            root_sk,
            root_vk,
            grant,
            key: [0x55; 32],
        }
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let frame = a
            .seal(ROOT_NOW + 1, Rights::SENSOR_READ, b"temp=21.5")
            .expect("seal");
        let opened = b.open(&frame, ROOT_NOW + 1).expect("open");
        assert_eq!(opened.plaintext, b"temp=21.5");
        assert_eq!(opened.counter, 1);
    }

    #[test]
    fn counters_increase_monotonically() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let f1 = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"a").expect("seal");
        let f2 = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"b").expect("seal");
        assert_eq!(f1.counter, 1);
        assert_eq!(f2.counter, 2);
    }

    #[test]
    fn missing_right_is_refused_before_any_crypto() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        assert_eq!(
            a.seal(ROOT_NOW, Rights::NET_EGRESS, b"exfiltrate")
                .unwrap_err(),
            HandshakeError::RightsNotPermitted
        );
    }

    #[test]
    fn revoked_session_cannot_seal_or_open() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        a.revoke();

        assert!(a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").is_err());
        assert_eq!(
            a.open(&frame, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
        );
    }

    #[test]
    fn expired_capability_blocks_sealing() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        assert!(a.seal(ROOT_NOW + 600, Rights::SENSOR_READ, b"x").is_err());
        assert!(a.is_revoked());
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"once")
            .expect("seal");
        b.open(&frame, ROOT_NOW).expect("first");
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn garbage_does_not_burn_counters() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let mut frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"real")
            .expect("seal");
        frame.ciphertext[0] ^= 0xFF;
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);

        // The genuine frame still opens: authentication failure did not consume counter 1.
        let good = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"real")
            .expect("seal");
        b.open(&good, ROOT_NOW).expect("genuine frame accepted");
    }

    #[test]
    fn wrong_session_key_cannot_open() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b =
            Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, [0x99; 32]).expect("session");

        let frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn frame_for_other_capability_is_refused() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let mut frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        frame.capability_id = [0xAA; 16];
        assert_eq!(
            b.open(&frame, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
        );
    }

    /// A rotation keeps exactly one epoch of history, so a frame reordered across the boundary
    /// still opens while anything older is refused. That is the deliberate trade: one epoch of
    /// compromise window on the *receiver* in exchange for not losing reordered traffic. A
    /// forward attacker gains nothing, because the ratchet is one-way and they cannot derive
    /// the previous key.
    #[test]
    fn rotation_keeps_one_epoch_of_history_and_no_more() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let old = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"old").expect("seal");

        a.rotate([0x77; 32]);
        b.rotate([0x77; 32]);
        assert_eq!(a.epoch(), 1);

        assert_eq!(
            b.open(&old, ROOT_NOW)
                .expect("one epoch back still opens")
                .plaintext,
            b"old"
        );

        let new = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"new").expect("seal");
        let opened = b.open(&new, ROOT_NOW).expect("new epoch opens");
        assert_eq!(opened.plaintext, b"new");
    }

    #[test]
    fn grant_from_another_root_is_refused_at_session_creation() {
        let e = env(Rights::SENSOR_READ);
        let foreign = HybridSigningKey::generate()
            .expect("entropy")
            .verifying_key();
        assert!(Session::from_grant(&e.grant, &foreign, ROOT_NOW, e.key).is_err());
    }

    /// The KEM output is bound to the device id and handshake nonce, so two sessions that share
    /// a shared secret still cannot read each other's frames. This is the property that makes a
    /// leaked `session_key` from one handshake useless in another.
    #[test]
    fn same_shared_secret_in_different_sessions_yields_incompatible_keys() {
        // Same device and the same shared secret, but a different handshake nonce: a distinct
        // session whose signature still verifies, so the key separation is what refuses the frame.
        let a_env = env_with_nonce(Rights::SENSOR_READ, [0x44; 32]);
        let b_env = env_with_nonce(Rights::SENSOR_READ, [0x99; 32]);

        let mut a =
            Session::from_grant(&a_env.grant, &a_env.root_vk, ROOT_NOW, [0x55; 32]).expect("a");
        let mut b =
            Session::from_grant(&b_env.grant, &b_env.root_vk, ROOT_NOW, [0x55; 32]).expect("b");

        // Device id and epoch both match, so the header checks pass; the AEAD tag is what fails,
        // proving the derived keys differ rather than the labels.
        let frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"secret")
            .expect("seal");
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);
    }

    /// Forward secrecy, stated precisely: the session retains one epoch of history, so a frame
    /// is readable until the session has moved *two* epochs past it. After that the key is gone
    /// and the frame is permanently unreadable.
    #[test]
    fn ratchet_destroys_old_frames_once_two_epochs_have_passed() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let old = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"before")
            .expect("seal");

        for _ in 0..2 {
            a.rotate([0x77; 32]);
            b.rotate([0x77; 32]);
        }

        assert_eq!(
            b.open(&old, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
        );
    }

    /// A rotation must not be a relabelling: if the caller passes a different `mix_in`, the
    /// derived keys diverge and the peers can no longer talk. That proves the new key depends on
    /// the mix, not just on the epoch number.
    #[test]
    fn rotation_with_different_mix_in_diverges() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        a.rotate([0x77; 32]);
        b.rotate([0x88; 32]);

        // Both sides are on epoch 1, so the epoch check passes and the failure surfaces at the
        // AEAD tag — which is exactly the point: the keys diverged, not the labels.
        let frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);
    }

    /// The epoch is bound into the derivation, so replaying the same `mix_in` at a later epoch
    /// still produces a different key.
    #[test]
    fn repeated_mix_in_at_a_new_epoch_still_advances_the_key() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        for _ in 0..2 {
            a.rotate([0x77; 32]);
            b.rotate([0x77; 32]);
        }
        assert_eq!(a.epoch(), 2);

        let frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        let opened = b.open(&frame, ROOT_NOW).expect("same epoch opens");
        assert_eq!(opened.plaintext, b"x");
    }

    // --- automatic ratcheting ---------------------------------------------------------

    #[test]
    fn auto_ratchet_advances_the_epoch_without_a_caller() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key)
            .expect("a")
            .with_auto_ratchet(3);

        for _ in 0..3 {
            a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        }
        assert_eq!(
            a.epoch(),
            1,
            "three frames should trip a threshold of three"
        );

        a.seal(ROOT_NOW, Rights::SENSOR_READ, b"y").expect("seal");
        assert_eq!(a.epoch(), 1, "the fourth frame is still in epoch 1");
    }

    #[test]
    fn a_peer_that_never_ratchets_still_opens_after_auto_ratchet() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key)
            .expect("a")
            .with_auto_ratchet(2);
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        // `a` ratchets on its own; `b` has no threshold and must follow from the wire.
        for i in 0..5 {
            let frame = a
                .seal(ROOT_NOW, Rights::SENSOR_READ, format!("m{i}").as_bytes())
                .expect("seal");
            let opened = b.open(&frame, ROOT_NOW).expect("peer catches up");
            assert_eq!(opened.plaintext, format!("m{i}").as_bytes());
        }
        assert!(b.epoch() >= 1, "the follower advanced too");
    }

    #[test]
    fn a_frame_from_one_epoch_back_still_opens() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let in_flight = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"old").expect("seal");
        a.rotate([0x77; 32]);
        b.rotate([0x77; 32]);

        let opened = b.open(&in_flight, ROOT_NOW).expect("reordered frame opens");
        assert_eq!(opened.plaintext, b"old");
    }

    #[test]
    fn a_frame_two_epochs_back_is_refused() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let stale = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"stale")
            .expect("seal");
        for _ in 0..2 {
            a.rotate([0x77; 32]);
            b.rotate([0x77; 32]);
        }

        // Only one epoch of history is kept; older keys are gone on purpose.
        assert_eq!(
            b.open(&stale, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
        );
    }

    /// A forged frame claiming a far-future epoch must not move the receiver's state. If it did,
    /// an unauthenticated packet could destroy the keys needed for real in-flight traffic.
    #[test]
    fn a_forged_future_epoch_does_not_advance_the_receiver() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let mut frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"real")
            .expect("seal");
        frame.epoch = 5;
        frame.ciphertext[0] ^= 0xFF;

        assert!(b.open(&frame, ROOT_NOW).is_err());
        assert_eq!(b.epoch(), 0, "a rejected frame must not commit an advance");

        // The receiver must still work normally afterwards.
        let good = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"after")
            .expect("seal");
        assert_eq!(
            b.open(&good, ROOT_NOW).expect("still works").plaintext,
            b"after"
        );
    }

    #[test]
    fn an_epoch_beyond_the_skip_limit_is_refused() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let mut frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        frame.epoch = MAX_EPOCH_SKIP + 1;

        assert_eq!(
            b.open(&frame, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
        );
        assert_eq!(b.epoch(), 0);
    }

    // --- rekey (post-compromise security) ---------------------------------------------

    #[test]
    fn rekey_advances_both_peers_and_keeps_them_talking() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        a.rekey([0xAA; 32]);
        b.rekey([0xAA; 32]);
        assert_eq!(a.epoch(), 1);

        let frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"post")
            .expect("seal");
        assert_eq!(b.open(&frame, ROOT_NOW).expect("opens").plaintext, b"post");
    }

    /// The point of a rekey: a peer holding only the old key cannot follow. Here `b` performs a
    /// ratchet instead of the rekey, which is exactly what an attacker with the old key could
    /// compute — and it must fail.
    #[test]
    fn a_peer_with_only_the_old_key_cannot_follow_a_rekey() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut attacker = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        a.rekey([0xAA; 32]);
        // An attacker who captured the pre-rekey key can only ratchet; they lack the new secret.
        attacker.rotate([0xAA; 32]);
        assert_eq!(attacker.epoch(), a.epoch());

        let frame = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"secret")
            .expect("seal");
        assert_eq!(
            attacker.open(&frame, ROOT_NOW).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn rekey_with_a_different_secret_diverges() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        a.rekey([0xAA; 32]);
        b.rekey([0xBB; 32]);

        let frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn auto_ratchet_threshold_of_zero_is_clamped_to_one() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key)
            .expect("a")
            .with_auto_ratchet(0);

        a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        assert_eq!(a.epoch(), 1);
    }

    #[test]
    fn grant_with_no_rights_is_refused() {
        let e = env(Rights::NONE);
        assert!(Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).is_err());
    }

    #[test]
    fn tampered_counter_is_caught_by_aead() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let mut frame = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"x").expect("seal");
        // Attacker rewinds the counter to make an old frame look fresh.
        frame.counter = 0;
        assert_eq!(b.open(&frame, ROOT_NOW).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn session_keeps_working_after_the_root_key_is_dropped() {
        // A session must hold only what it needs to seal and open. If it secretly kept the
        // root signing key, an attacker who compromised the bridge process could mint new
        // grants from it, so dropping the key here proves the session does not depend on it.
        let e = env(Rights::SENSOR_READ);
        let mut session =
            Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        drop(e.root_sk);
        drop(e.root_vk);

        let frame = session
            .seal(ROOT_NOW + 1, Rights::SENSOR_READ, b"still works")
            .expect("seal without root key");
        let opened = session.open(&frame, ROOT_NOW + 1).expect("open");
        assert_eq!(opened.plaintext, b"still works");
    }
}
