//! Hybrid post-quantum + classical cryptography engine.
//!
//! ## Design rule
//!
//! Every hybrid primitive here is **AND-composed**, never OR-composed:
//!
//! * a signature verifies only if *both* the ECDSA P-384 and the ML-DSA-87 signatures verify;
//! * the KEM shared secret is derived from *both* the ML-KEM-1024 and the ECDH P-384 secrets.
//!
//! OR-composition is the classic mistake: it hands an attacker the weaker of the two
//! primitives. AND-composition means a forger must break both, so the scheme is at least as
//! strong as its strongest half against any single adversary.
//!
//! ## What this crate does *not* claim
//!
//! These are pure-Rust implementations. They are not constant-time-audited on every target,
//! not formally verified, and the ML-KEM/ML-DSA crates say so themselves. Treat this as a
//! correct *composition* of vetted building blocks, and put the root key in an HSM or TPM
//! rather than in process memory.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]
// Tests assert on failures, so they are allowed to unwrap and panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)
)]

mod aead;
mod error;
mod grant_tag;
mod grant_v2;
mod kdf;
mod kem;
mod replay;
mod rng;
mod seeded_rng;
mod sign;
mod tri;

pub use aead::{open, seal, SealingKey};
pub use error::CryptoError;
pub use grant_tag::{grant_tag, grant_wire, verify_grant_tag, GrantKey, GRANT_TAG_LEN};
pub use grant_v2::{
    grant_v2_decode, grant_v2_encode, grant_v2_encode_parts, GrantV2, GRANT_V2_MAGIC,
    GRANT_V2_VERSION,
};
pub use kdf::{ratchet, rekey, session_key};
pub use kem::{HybridCiphertext, KemKeyPair, RecipientPublicKey};
pub use replay::ReplayWindow;
pub use rng::fill_random;
pub use sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
pub use tri::{
    TriSignature, TriSigningKey, TriVerifyingKey, SLH_SEED_LEN, SLH_SIG_LEN, SLH_VK_LEN,
};

/// Domain-separation labels. Changing one is a wire-format break, so they are versioned.
pub mod labels {
    /// Prefix for hybrid signature messages.
    pub const SIGN: &[u8] = b"SOVEREIGN/v1/hybrid-sign";
    /// HKDF `info` for the hybrid KEM combiner.
    pub const KEM: &[u8] = b"SOVEREIGN/v1/hybrid-kem";
    /// Prefix for capability tokens signed by the root CA.
    pub const CAPABILITY: &[u8] = b"SOVEREIGN/v1/capability";
    /// Prefix for attestation responses.
    pub const ATTESTATION: &[u8] = b"SOVEREIGN/v1/attestation";
    /// HKDF `info` prefix for the per-session AEAD key.
    pub const SESSION: &[u8] = b"SOVEREIGN/v1/session-key";
    /// HKDF `info` prefix for an epoch ratchet step.
    pub const RATCHET: &[u8] = b"SOVEREIGN/v1/epoch-ratchet";
    /// HKDF `info` prefix for a rekey that mixes in a fresh KEM secret.
    pub const REKEY: &[u8] = b"SOVEREIGN/v1/epoch-rekey";
}

/// Sizes of the encoded public artefacts, exposed so callers can pre-size buffers.
pub mod sizes {
    /// ML-DSA-87 encoded verifying key.
    pub const ML_DSA_87_VK: usize = 2592;
    /// ML-DSA-87 encoded signature.
    pub const ML_DSA_87_SIG: usize = 4627;
    /// Uncompressed SEC1 encoding of a P-384 point.
    pub const P384_SEC1: usize = 97;
    /// Fixed-size ECDSA P-384 signature (`r || s`, 48 bytes each).
    pub const P384_SIG: usize = 96;
    /// Encoded capability token, as parsed by the kernel gate.
    pub const TOKEN: usize = 77;
    /// ML-KEM-1024 ciphertext.
    pub const ML_KEM_1024_CT: usize = 1568;
    /// ML-KEM-1024 encapsulation key.
    pub const ML_KEM_1024_EK: usize = 1568;
    /// Symmetric key length used for payload sealing.
    pub const SYMMETRIC_KEY: usize = 32;
}
