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
    /// `session_key` is the output of the hybrid KEM run during the handshake. It is *not*
    /// derived from the token, so possessing a token is not enough to open traffic.
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
            key: SealingKey::from_bytes(session_key),
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

    /// Rotate to a new epoch and key. The counter keeps increasing so a peer cannot use the
    /// rotation to replay old frames under a fresh epoch.
    pub fn rotate(&mut self, new_key: [u8; 32]) {
        self.key = SealingKey::from_bytes(new_key);
        self.epoch = self.epoch.wrapping_add(1);
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
        let root_sk = HybridSigningKey::generate().expect("entropy");
        let root_vk = root_sk.verifying_key();
        let token = CapabilityToken {
            device_id: [0x33; 16],
            rights,
            issued_at: ROOT_NOW,
            expires_at: ROOT_NOW + 600,
            counter_base: 1,
            handshake_nonce: [0x44; 32],
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
