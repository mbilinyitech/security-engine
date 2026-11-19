//! Authenticated encryption for payloads and capability tokens.
//!
//! XChaCha20-Poly1305 is chosen over AES-GCM because its 24-byte nonce makes random nonce
//! generation safe at any realistic message volume, so we never need stateful counters that
//! could reset after a reboot and cause catastrophic nonce reuse.

use chacha20poly1305::{
    aead::{Aead as _, KeyInit as _},
    XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{sizes, CryptoError};

/// A symmetric key held in locked-down, zeroizing memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealingKey([u8; sizes::SYMMETRIC_KEY]);

impl SealingKey {
    pub fn from_bytes(bytes: [u8; sizes::SYMMETRIC_KEY]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; sizes::SYMMETRIC_KEY] {
        &self.0
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey(<redacted>)")
    }
}

/// Encrypt `plaintext`, authenticating `aad` alongside it. Returns `(nonce, ciphertext)`.
///
/// The nonce is generated here from the OS CSPRNG; callers cannot supply one. That removes the
/// single most common AEAD misuse (nonce reuse) from the API surface entirely.
pub fn seal(
    key: &SealingKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce = [0u8; 24];
    crate::rng::fill_random(&mut nonce)?;

    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    Ok((nonce, ct))
}

/// Decrypt and authenticate. Any failure — wrong key, tampered ciphertext, tampered `aad` —
/// collapses into [`CryptoError::Decrypt`].
pub fn open(
    key: &SealingKey,
    aad: &[u8],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SealingKey {
        SealingKey::from_bytes([7u8; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let (nonce, ct) = seal(&key(), b"hdr", b"secret payload").expect("seal");
        let pt = open(&key(), b"hdr", &nonce, &ct).expect("open");
        assert_eq!(pt, b"secret payload");
    }

    #[test]
    fn nonces_are_unique_per_message() {
        let (n1, _) = seal(&key(), b"", b"a").expect("seal");
        let (n2, _) = seal(&key(), b"", b"a").expect("seal");
        assert_ne!(n1, n2);
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let (nonce, ct) = seal(&key(), b"hdr", b"payload").expect("seal");
        assert_eq!(
            open(&key(), b"hdX", &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (nonce, mut ct) = seal(&key(), b"hdr", b"payload").expect("seal");
        ct[0] ^= 0x01;
        assert_eq!(
            open(&key(), b"hdr", &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (nonce, ct) = seal(&key(), b"hdr", b"payload").expect("seal");
        let other = SealingKey::from_bytes([8u8; 32]);
        assert_eq!(
            open(&other, b"hdr", &nonce, &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }
}
