//! Kernel-facing authentication tag for a capability token.
//!
//! ## Why this exists
//!
//! The kernel module verifies a grant with `hmac(sha256)`, because a post-quantum verifier in
//! kernel space does not exist yet. That means the user-space side must produce exactly the
//! same tag, over exactly the same bytes, or nothing interoperates. This module is that side.
//!
//! The tag covers the **wire bytes** of the token, never a parsed struct. Struct layout depends
//! on the compiler: padding bytes and native endianness differ between the Rust and C builds, so
//! hashing a struct produces a tag that agrees with nothing. This was a real bug, found by
//! running the module in a VM against a tag made by an independent implementation.
//!
//! ## What this is not
//!
//! An HMAC with a symmetric root key is weaker than the hybrid ECDSA + ML-DSA-87 signature the
//! rest of the system uses: anyone holding the key can forge a grant. It exists because the
//! kernel can compute it today. When a PQ verifier lands in kernel space, this should be
//! replaced, not layered on top.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Length of the tag written after the 77-byte token.
pub const GRANT_TAG_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Compute the kernel-facing tag over a token's wire bytes.
pub fn grant_tag(root_key: &[u8; 32], token_wire: &[u8]) -> [u8; GRANT_TAG_LEN] {
    // HMAC accepts a key of any length, so this cannot fail; the expect is unreachable
    // rather than a real error path.
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(root_key).expect("HMAC accepts keys of any length");
    mac.update(token_wire);
    let out = mac.finalize().into_bytes();

    let mut tag = [0u8; GRANT_TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Verify a tag in constant time, as the kernel does.
pub fn verify_grant_tag(root_key: &[u8; 32], token_wire: &[u8], tag: &[u8]) -> bool {
    if tag.len() != GRANT_TAG_LEN {
        return false;
    }
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(root_key).expect("HMAC accepts keys of any length");
    mac.update(token_wire);
    // `verify_slice` is constant-time and length-checked; do not replace with `==`.
    mac.verify_slice(tag).is_ok()
}

/// Build the exact byte string the kernel expects: 77-byte token followed by the 32-byte tag.
pub fn grant_wire(root_key: &[u8; 32], token_wire: &[u8]) -> Vec<u8> {
    let tag = grant_tag(root_key, token_wire);
    let mut out = Vec::with_capacity(token_wire.len() + GRANT_TAG_LEN);
    out.extend_from_slice(token_wire);
    out.extend_from_slice(&tag);
    out
}

/// A root key held in memory, zeroized on drop.
///
/// Thin wrapper so callers cannot accidentally copy the key around in a `[u8; 32]` that never
/// gets cleared.
pub struct GrantKey([u8; 32]);

impl GrantKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn tag(&self, token_wire: &[u8]) -> [u8; GRANT_TAG_LEN] {
        grant_tag(&self.0, token_wire)
    }

    pub fn wire(&self, token_wire: &[u8]) -> Vec<u8> {
        grant_wire(&self.0, token_wire)
    }
}

impl Drop for GrantKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for GrantKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_wire() -> Vec<u8> {
        // version | device_id | rights | issued | expires | base | nonce
        let mut v = vec![1u8];
        v.extend_from_slice(&[0xAB; 16]);
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1000u64.to_be_bytes());
        v.extend_from_slice(&2000u64.to_be_bytes());
        v.extend_from_slice(&1u64.to_be_bytes());
        v.extend_from_slice(&[0xCD; 32]);
        assert_eq!(v.len(), 77);
        v
    }

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn matches_the_reference_vector_used_by_the_c_test() {
        // This exact tag is asserted in kernel/test_sov_core.c and was produced by CPython's
        // hashlib. All three implementations agreeing is the point.
        let expected = [
            0xcb, 0x3e, 0xe7, 0x67, 0x43, 0x1d, 0xa0, 0x1a, 0xa7, 0xf2, 0x0f, 0x54, 0x1e, 0x0c,
            0x6f, 0x61, 0x0e, 0x47, 0x4d, 0x4f, 0x52, 0x7e, 0x98, 0x4f, 0x10, 0xc2, 0x50, 0x25,
            0xac, 0x70, 0x94, 0x33,
        ];
        assert_eq!(grant_tag(&key(), &token_wire()), expected);
    }

    #[test]
    fn verification_accepts_a_good_tag_and_rejects_a_bad_one() {
        let k = key();
        let w = token_wire();
        let tag = grant_tag(&k, &w);

        assert!(verify_grant_tag(&k, &w, &tag));

        let mut bad = tag;
        bad[31] ^= 0x01;
        assert!(!verify_grant_tag(&k, &w, &bad));
    }

    #[test]
    fn every_single_bit_flip_in_the_tag_is_rejected() {
        let k = key();
        let w = token_wire();
        let tag = grant_tag(&k, &w);

        for byte in 0..GRANT_TAG_LEN {
            for bit in 0..8 {
                let mut bad = tag;
                bad[byte] ^= 1 << bit;
                assert!(!verify_grant_tag(&k, &w, &bad), "byte {byte} bit {bit}");
            }
        }
    }

    #[test]
    fn a_changed_token_byte_invalidates_the_tag() {
        let k = key();
        let mut w = token_wire();
        let tag = grant_tag(&k, &w);
        assert!(verify_grant_tag(&k, &w, &tag));

        // Escalate rights: the tag must notice.
        w[20] = 0xFF;
        assert!(!verify_grant_tag(&k, &w, &tag));
    }

    #[test]
    fn a_wrong_length_tag_is_refused_not_panicked_on() {
        let k = key();
        let w = token_wire();
        assert!(!verify_grant_tag(&k, &w, &[]));
        assert!(!verify_grant_tag(&k, &w, &[0u8; 31]));
        assert!(!verify_grant_tag(&k, &w, &[0u8; 33]));
    }

    #[test]
    fn the_wire_is_token_then_tag() {
        let k = key();
        let w = token_wire();
        let wire = grant_wire(&k, &w);

        assert_eq!(wire.len(), 77 + 32);
        assert_eq!(&wire[..77], &w[..]);
        assert_eq!(&wire[77..], &grant_tag(&k, &w)[..]);
    }

    #[test]
    fn a_different_key_produces_a_different_tag() {
        let w = token_wire();
        let mut other = key();
        other[0] ^= 0xFF;
        assert_ne!(grant_tag(&key(), &w), grant_tag(&other, &w));
    }

    #[test]
    fn the_key_wrapper_matches_the_free_functions() {
        let k = key();
        let w = token_wire();
        let gk = GrantKey::new(k);
        assert_eq!(gk.tag(&w), grant_tag(&k, &w));
        assert_eq!(gk.wire(&w), grant_wire(&k, &w));
        assert_eq!(format!("{gk:?}"), "GrantKey(<redacted>)");
    }
}
