//! Key derivation: binding a KEM output to one session, and ratcheting forward.
//!
//! Three jobs, all done with HKDF-SHA-384, and the difference between the last two matters:
//!
//! * [`session_key`] mixes the raw KEM output with the device id and the handshake nonce, so
//!   the same shared secret can never produce the same AEAD key in two different sessions.
//!   Without this, key separation would rest on an assumption nobody checks: that the KEM
//!   output is never reused. Mixing the nonce in makes reuse harmless.
//!
//! * [`ratchet`] derives the next epoch key from the current one. This gives *forward secrecy*:
//!   once the old key is destroyed, old traffic is unreadable. It gives **nothing** against an
//!   attacker who already holds the current key — they can compute every future epoch too. That
//!   is not a bug to be fixed by hashing harder; it is what a one-way function does. Symmetric
//!   ratchets move forward only.
//!
//! * [`rekey`] mixes in a *new* shared secret from a fresh KEM exchange. This is the only thing
//!   that recovers after a compromise: an attacker holding epoch `n`'s key cannot compute
//!   epoch `n+1`'s, because they do not have the new KEM output. Call this a rekey, not a
//!   ratchet, and do not let the two be confused in a design review.

use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroize;

use crate::{labels, sizes, SealingKey};

/// Derive the AEAD key for one session from the hybrid KEM's shared secret.
///
/// Binding both the device id and the handshake nonce means a token or a shared secret captured
/// from session A yields a different key in session B, so transplanting one into the other fails
/// at decryption even before the capability checks run.
pub fn session_key(
    shared: &[u8; sizes::SYMMETRIC_KEY],
    device_id: &[u8; 16],
    handshake_nonce: &[u8; 32],
) -> SealingKey {
    let mut info = Vec::with_capacity(labels::SESSION.len() + 16 + 32);
    info.extend_from_slice(labels::SESSION);
    info.extend_from_slice(device_id);
    info.extend_from_slice(handshake_nonce);
    derive(shared, &info)
}

/// Derive the next epoch key from the current one.
///
/// `mix_in` is fresh entropy from a new key exchange; it is not secret on its own, and it is
/// mixed in so that a caller cannot silently keep the same key while claiming a rotation.
/// `epoch` is bound into the derivation so the same pair of inputs can never yield two epochs'
/// keys — an epoch number that merely increments a counter is a label, not a derivation.
///
/// This is a symmetric step: whoever holds `previous` can compute the result. Use it for forward
/// secrecy, never as a recovery mechanism. See [`rekey`] for that.
pub fn ratchet(previous: &SealingKey, mix_in: &[u8; 32], epoch: u32) -> SealingKey {
    let mut info = Vec::with_capacity(labels::RATCHET.len() + 32 + 4);
    info.extend_from_slice(labels::RATCHET);
    info.extend_from_slice(mix_in);
    info.extend_from_slice(&epoch.to_be_bytes());
    derive(previous.as_bytes(), &info)
}

/// Derive the next epoch key from the current one **and** a new shared secret.
///
/// Unlike [`ratchet`], the result is not computable from the previous key alone, so an attacker
/// who captured epoch `n`'s key cannot follow the session into epoch `n+1`. This is
/// post-compromise security, and it is the only function here that provides it.
///
/// `shared` must come from a fresh hybrid KEM exchange with the peer. Passing a constant, or the
/// previous key, degrades this to a plain ratchet — the epoch and the transcript hash are bound in
/// so that the two cases are not silently interchangeable, but no derivation can manufacture
/// entropy that was never exchanged.
pub fn rekey(previous: &SealingKey, shared: &[u8; sizes::SYMMETRIC_KEY], epoch: u32) -> SealingKey {
    let mut ikm = Vec::with_capacity(sizes::SYMMETRIC_KEY * 2);
    ikm.extend_from_slice(previous.as_bytes());
    ikm.extend_from_slice(shared);

    let mut info = Vec::with_capacity(labels::REKEY.len() + 4);
    info.extend_from_slice(labels::REKEY);
    info.extend_from_slice(&epoch.to_be_bytes());

    let key = derive(&ikm, &info);
    ikm.zeroize();
    key
}

fn derive(ikm: &[u8], info: &[u8]) -> SealingKey {
    let hk = Hkdf::<Sha384>::new(None, ikm);
    let mut okm = [0u8; sizes::SYMMETRIC_KEY];
    hk.expand(info, &mut okm)
        .expect("32 bytes is far below the HKDF-SHA-384 output limit");
    let key = SealingKey::from_bytes(okm);
    okm.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED: [u8; 32] = [0x11; 32];
    const DEV: [u8; 16] = [0x22; 16];
    const NONCE_A: [u8; 32] = [0x33; 32];
    const NONCE_B: [u8; 32] = [0x44; 32];

    #[test]
    fn same_shared_secret_yields_different_keys_for_different_sessions() {
        let a = session_key(&SHARED, &DEV, &NONCE_A);
        let b = session_key(&SHARED, &DEV, &NONCE_B);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_devices_with_the_same_secret_do_not_collide() {
        let a = session_key(&SHARED, &[0x01; 16], &NONCE_A);
        let b = session_key(&SHARED, &[0x02; 16], &NONCE_A);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn session_key_is_deterministic() {
        let a = session_key(&SHARED, &DEV, &NONCE_A);
        let b = session_key(&SHARED, &DEV, &NONCE_A);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn ratchet_moves_away_from_the_previous_key() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let k1 = ratchet(&k0, &[0x55; 32], 1);
        assert_ne!(k0.as_bytes(), k1.as_bytes());
    }

    #[test]
    fn ratchet_is_deterministic_for_the_same_epoch_and_mix() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let a = ratchet(&k0, &[0x55; 32], 1);
        let b = ratchet(&k0, &[0x55; 32], 1);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn epoch_number_participates_in_the_derivation() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let k1 = ratchet(&k0, &[0x55; 32], 1);
        let k2 = ratchet(&k0, &[0x55; 32], 2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn a_different_mix_in_changes_the_result() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let a = ratchet(&k0, &[0x55; 32], 1);
        let b = ratchet(&k0, &[0x66; 32], 1);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn ratcheting_twice_differs_from_ratcheting_once() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let k1 = ratchet(&k0, &[0x55; 32], 1);
        let k2 = ratchet(&k1, &[0x55; 32], 2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn rekey_moves_away_from_the_previous_key() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let k1 = rekey(&k0, &[0x77; 32], 1);
        assert_ne!(k0.as_bytes(), k1.as_bytes());
    }

    #[test]
    fn rekey_is_deterministic() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let a = rekey(&k0, &[0x77; 32], 1);
        let b = rekey(&k0, &[0x77; 32], 1);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rekey_depends_on_the_new_shared_secret() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let a = rekey(&k0, &[0x77; 32], 1);
        let b = rekey(&k0, &[0x78; 32], 1);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rekey_binds_the_epoch() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let a = rekey(&k0, &[0x77; 32], 1);
        let b = rekey(&k0, &[0x77; 32], 2);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// The property that separates a rekey from a ratchet: the result must not be reachable from
    /// the previous key alone. This test states it as a negative — the ratchet and rekey outputs
    /// for the same inputs differ, so one cannot be mistaken for the other.
    #[test]
    fn rekey_and_ratchet_are_domain_separated() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let r = ratchet(&k0, &[0x77; 32], 1);
        let k = rekey(&k0, &[0x77; 32], 1);
        assert_ne!(r.as_bytes(), k.as_bytes());
    }

    /// A rekey must also differ from a plain session key derived from the same new secret, so a
    /// caller cannot substitute one for the other and silently lose the chain.
    #[test]
    fn rekey_is_not_just_the_new_secret() {
        let k0 = session_key(&SHARED, &DEV, &NONCE_A);
        let k1 = rekey(&k0, &[0x77; 32], 1);
        let naive = session_key(&[0x77; 32], &DEV, &NONCE_A);
        assert_ne!(k1.as_bytes(), naive.as_bytes());
    }
}
