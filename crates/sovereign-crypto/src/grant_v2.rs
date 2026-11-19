//! Hybrid-signed capability grant, for kernels that can verify both halves.
//!
//! ## Why this exists
//!
//! [`crate::grant_tag`] authenticates a token with `hmac(sha256)`. That is one symmetric key:
//! whoever holds it can mint any grant, and a kernel compromise that leaks it forges grants
//! forever. The rest of the system signs with ECDSA P-384 **and** ML-DSA-87 precisely so that
//! no single secret does that. This module is the wire format for carrying that signature to a
//! kernel which verifies both halves itself.
//!
//! ## What is *not* in the blob
//!
//! The verifying key is not here. If it were, an attacker would supply their own key alongside
//! their own signature and the check would be vacuous. The key belongs in the kernel module,
//! compiled in or provisioned through a sealed channel — somewhere the attacker cannot write.
//!
//! ## Layout
//!
//! ```text
//! magic(4) = "SOVG" | version(1) = 2 | token(77)
//!   | u16_be(ecdsa_sig_len) | ecdsa_sig (r||s, 96)
//!   | u16_be(mldsa_sig_len) | mldsa_sig (4627)
//! ```
//!
//! The signature covers the **token wire bytes** under [`labels::CAPABILITY`], the same domain
//! and the same bytes the bridge signs elsewhere. Nothing in this header is signed, and it does
//! not need to be: the parser rejects any blob whose declared lengths do not match the exact
//! sizes, so there is no room to reinterpret the payload.

use crate::{
    error::CryptoError,
    labels,
    sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey},
};

/// Identifies a hybrid-signed grant, as opposed to a v1 `hmac` blob.
pub const GRANT_V2_MAGIC: [u8; 4] = *b"SOVG";
/// Format version. v1 had no magic and no version byte.
pub const GRANT_V2_VERSION: u8 = 2;

/// Fixed size of the header before the token.
pub const GRANT_V2_HEADER_LEN: usize = 4 + 1;
/// Total fixed overhead around the variable signature bytes.
pub const GRANT_V2_OVERHEAD: usize = GRANT_V2_HEADER_LEN + 2 + 2;

/// Encode a hybrid-signed grant over `token_wire`.
///
/// `token_wire` must be exactly the 77-byte token encoding; the kernel parses that layout
/// itself and a mismatch would be caught there, but failing here gives a better error.
pub fn grant_v2_encode(key: &HybridSigningKey, token_wire: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig = key.sign(labels::CAPABILITY, token_wire)?;
    Ok(grant_v2_encode_parts(token_wire, &sig))
}

/// Encode from an already-computed signature, so a caller can sign once and use it twice.
pub fn grant_v2_encode_parts(token_wire: &[u8], sig: &HybridSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(GRANT_V2_OVERHEAD + token_wire.len() + sig.encode().len());
    out.extend_from_slice(&GRANT_V2_MAGIC);
    out.push(GRANT_V2_VERSION);
    out.extend_from_slice(token_wire);
    out.extend_from_slice(&(sig.ecdsa.len() as u16).to_be_bytes());
    out.extend_from_slice(&sig.ecdsa);
    out.extend_from_slice(&(sig.mldsa.len() as u16).to_be_bytes());
    out.extend_from_slice(&sig.mldsa);
    out
}

/// A parsed hybrid grant: the token bytes and the two signature halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantV2<'a> {
    /// The 77-byte token, exactly as signed.
    pub token: &'a [u8],
    /// ECDSA half, `r || s`.
    pub ecdsa: &'a [u8],
    /// ML-DSA half.
    pub mldsa: &'a [u8],
}

/// Parse a hybrid grant, rejecting anything whose lengths do not add up.
///
/// Every length is checked against the remaining input before it is used, so a hostile blob
/// cannot make this allocate or slice out of bounds.
pub fn grant_v2_decode(blob: &[u8]) -> Result<GrantV2<'_>, CryptoError> {
    let rest = blob;

    let (magic, after_magic) = rest.split_at_checked(4).ok_or(CryptoError::Encoding)?;
    if magic != GRANT_V2_MAGIC {
        return Err(CryptoError::Encoding);
    }
    let (&version, after_version) = after_magic.split_first().ok_or(CryptoError::Encoding)?;
    if version != GRANT_V2_VERSION {
        return Err(CryptoError::Encoding);
    }

    let (token, after_token) = after_version
        .split_at_checked(crate::sizes::TOKEN)
        .ok_or(CryptoError::Encoding)?;

    let (ecdsa_len_bytes, after_ecdsa_len) = after_token
        .split_at_checked(2)
        .ok_or(CryptoError::Encoding)?;
    let ecdsa_len = u16::from_be_bytes([ecdsa_len_bytes[0], ecdsa_len_bytes[1]]) as usize;
    if ecdsa_len != crate::sizes::P384_SIG {
        return Err(CryptoError::Encoding);
    }
    let (ecdsa, after_ecdsa) = after_ecdsa_len
        .split_at_checked(ecdsa_len)
        .ok_or(CryptoError::Encoding)?;

    let (mldsa_len_bytes, after_mldsa_len) = after_ecdsa
        .split_at_checked(2)
        .ok_or(CryptoError::Encoding)?;
    let mldsa_len = u16::from_be_bytes([mldsa_len_bytes[0], mldsa_len_bytes[1]]) as usize;
    if mldsa_len != crate::sizes::ML_DSA_87_SIG {
        return Err(CryptoError::Encoding);
    }
    let (mldsa, tail) = after_mldsa_len
        .split_at_checked(mldsa_len)
        .ok_or(CryptoError::Encoding)?;

    // No trailing bytes: a longer blob is a different format, not this one.
    if !tail.is_empty() {
        return Err(CryptoError::Encoding);
    }

    Ok(GrantV2 {
        token,
        ecdsa,
        mldsa,
    })
}

impl GrantV2<'_> {
    /// Verify both halves against `vk` over the token bytes.
    ///
    /// Present so the Rust side can prove a blob it just produced is one the kernel will
    /// accept, before anyone writes it to a device node.
    pub fn verify(&self, vk: &HybridVerifyingKey) -> Result<(), CryptoError> {
        let sig = HybridSignature {
            ecdsa: self.ecdsa.try_into().map_err(|_| CryptoError::Encoding)?,
            mldsa: self.mldsa.to_vec(),
        };
        vk.verify(labels::CAPABILITY, self.token, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizes;

    fn token() -> Vec<u8> {
        // A well-formed 77-byte token body; the contents do not matter for encoding tests.
        let mut t = vec![0u8; sizes::TOKEN];
        t[0] = 1;
        t[17..21].copy_from_slice(&0x0000_0004u32.to_be_bytes());
        t
    }

    fn key() -> HybridSigningKey {
        HybridSigningKey::from_seeds([0x11; 48], [0x22; 32])
    }

    #[test]
    fn roundtrip_and_both_halves_verify() {
        let k = key();
        let t = token();
        let blob = grant_v2_encode(&k, &t).expect("encode");
        let parsed = grant_v2_decode(&blob).expect("decode");

        assert_eq!(parsed.token, &t[..]);
        assert_eq!(parsed.ecdsa.len(), sizes::P384_SIG);
        assert_eq!(parsed.mldsa.len(), sizes::ML_DSA_87_SIG);
        parsed.verify(&k.verifying_key()).expect("verify");
    }

    #[test]
    fn the_blob_starts_with_magic_and_version() {
        let blob = grant_v2_encode(&key(), &token()).expect("encode");
        assert_eq!(&blob[..4], b"SOVG");
        assert_eq!(blob[4], 2);
        assert_eq!(
            blob.len(),
            GRANT_V2_OVERHEAD + sizes::TOKEN + sizes::P384_SIG + sizes::ML_DSA_87_SIG
        );
    }

    #[test]
    fn a_tampered_token_fails_verification() {
        let k = key();
        let blob = grant_v2_encode(&k, &token()).expect("encode");
        let mut bad = blob.clone();
        // Escalate rights inside the token.
        bad[GRANT_V2_HEADER_LEN + 20] ^= 0xFF;
        let parsed = grant_v2_decode(&bad).expect("still parses");
        assert!(parsed.verify(&k.verifying_key()).is_err());
    }

    #[test]
    fn a_tampered_ecdsa_half_fails_verification() {
        let k = key();
        let blob = grant_v2_encode(&k, &token()).expect("encode");
        let mut bad = blob.clone();
        let off = GRANT_V2_HEADER_LEN + sizes::TOKEN + 2 + 10;
        bad[off] ^= 0x01;
        let parsed = grant_v2_decode(&bad).expect("still parses");
        assert!(parsed.verify(&k.verifying_key()).is_err());
    }

    #[test]
    fn a_tampered_mldsa_half_fails_verification() {
        let k = key();
        let blob = grant_v2_encode(&k, &token()).expect("encode");
        let mut bad = blob.clone();
        let off = GRANT_V2_HEADER_LEN + sizes::TOKEN + 2 + sizes::P384_SIG + 2 + 32;
        bad[off] ^= 0x01;
        let parsed = grant_v2_decode(&bad).expect("still parses");
        assert!(parsed.verify(&k.verifying_key()).is_err());
    }

    #[test]
    fn a_signature_from_another_key_fails() {
        let blob = grant_v2_encode(&key(), &token()).expect("encode");
        let parsed = grant_v2_decode(&blob).expect("decode");
        let other = HybridSigningKey::from_seeds([0x33; 48], [0x44; 32]);
        assert!(parsed.verify(&other.verifying_key()).is_err());
    }

    #[test]
    fn wrong_magic_is_refused() {
        let mut blob = grant_v2_encode(&key(), &token()).expect("encode");
        blob[0] = b'X';
        assert_eq!(grant_v2_decode(&blob).unwrap_err(), CryptoError::Encoding);
    }

    #[test]
    fn wrong_version_is_refused() {
        let mut blob = grant_v2_encode(&key(), &token()).expect("encode");
        blob[4] = 1;
        assert_eq!(grant_v2_decode(&blob).unwrap_err(), CryptoError::Encoding);
    }

    #[test]
    fn truncation_is_refused_at_every_length() {
        let blob = grant_v2_encode(&key(), &token()).expect("encode");
        for cut in [0, 3, 4, 5, 5 + sizes::TOKEN - 1, blob.len() - 1] {
            assert!(
                grant_v2_decode(&blob[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut blob = grant_v2_encode(&key(), &token()).expect("encode");
        blob.push(0);
        assert_eq!(grant_v2_decode(&blob).unwrap_err(), CryptoError::Encoding);
    }

    #[test]
    fn a_declared_length_larger_than_the_data_is_refused() {
        let mut blob = grant_v2_encode(&key(), &token()).expect("encode");
        // Inflate the ML-DSA length field without adding data.
        let off = GRANT_V2_HEADER_LEN + sizes::TOKEN + 2 + sizes::P384_SIG;
        blob[off] = 0x7F;
        assert_eq!(grant_v2_decode(&blob).unwrap_err(), CryptoError::Encoding);
    }
}
