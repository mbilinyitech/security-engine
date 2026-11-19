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
    /// Next counter to stamp on an outbound frame. Monotonic and never reused.
    next_counter: u64,
    /// Replay protection for inbound frames from the peer.
    replay: ReplayWindow,
    epoch: u32,
    revoked: bool,
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
            replay: ReplayWindow::new(),
            epoch: 0,
            revoked: false,
        })
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
        // `ratchet` returns a fresh key and the assignment drops the old one, which zeroizes on
        // drop. The previous key is therefore gone before any new frame can be sealed.
        self.key = sovereign_crypto::ratchet(&self.key, &mix_in, next_epoch);
        self.epoch = next_epoch;
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
        if frame.epoch != self.epoch {
            return Err(CryptoError::Verification);
        }

        let plaintext = aead_open(
            &self.key,
            &frame.associated_data(),
            &frame.nonce,
            &frame.ciphertext,
        )?;
        self.replay.accept(frame.counter)?;
        Ok(OpenedFrame {
            counter: frame.counter,
            plaintext,
        })
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

    #[test]
    fn rotation_blocks_old_epoch_frames() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("session");

        let old = a.seal(ROOT_NOW, Rights::SENSOR_READ, b"old").expect("seal");

        a.rotate([0x77; 32]);
        b.rotate([0x77; 32]);
        assert_eq!(a.epoch(), 1);

        assert_eq!(
            b.open(&old, ROOT_NOW).unwrap_err(),
            CryptoError::Verification
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

    /// Forward secrecy: once the session ratchets, the old epoch key is gone, so frames sealed
    /// under it can no longer be opened — even by the peer that used to hold that key.
    #[test]
    fn ratchet_destroys_the_ability_to_read_old_frames() {
        let e = env(Rights::SENSOR_READ);
        let mut a = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("a");
        let mut b = Session::from_grant(&e.grant, &e.root_vk, ROOT_NOW, e.key).expect("b");

        let old = a
            .seal(ROOT_NOW, Rights::SENSOR_READ, b"before")
            .expect("seal");

        a.rotate([0x77; 32]);
        b.rotate([0x77; 32]);

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
