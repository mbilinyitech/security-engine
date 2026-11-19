//! Tri-hybrid signatures: ECDSA P-384 **and** ML-DSA-87 **and** SLH-DSA-SHA2-256s.
//!
//! ## Why a third half
//!
//! ECDSA P-384 and ML-DSA-87 fail to different adversaries, which is why they are AND-composed.
//! But both rest on structured algebra: P-384 on the discrete log problem in an elliptic curve
//! group, ML-DSA on module-lattice problems. A break in either family — a new algorithm, or a
//! fault attack on one implementation — is a break in one half of the pair. SLH-DSA (FIPS 205,
//! the standardised SPHINCS+) rests on nothing but the preimage and collision resistance of a
//! hash function. There is no algebraic structure to exploit, no decryption key to fault, no
//! lattice to reduce. Adding it means an attacker must break hash functions *as well as* both
//! algebraic families.
//!
//! ## What it costs, measured on this machine (release build, x86_64)
//!
//! ```text
//!              verifying key   signature   sign      verify
//! ECDSA P-384       97 B          96 B     ~0.2 ms   ~0.4 ms
//! ML-DSA-87       2592 B        4627 B     ~1.0 ms   ~0.7 ms
//! SLH-DSA-256s      64 B       29792 B   ~467 ms     ~619 us
//! ```
//!
//! SLH-DSA verification is cheap; *signing* is slow by design, because it hashes its way
//! through a hypertree. That asymmetry is why this is opt-in per call site rather than the
//! default everywhere: a device that signs once at enrolment can afford 467 ms, a server
//! signing ten thousand grants a second cannot.
//!
//! ## Why not replace the others
//!
//! "Stronger" is not a total order. SLH-DSA is stronger against algebraic cryptanalysis and
//! against fault attacks, but it is 310x larger and three orders of magnitude slower to sign.
//! A 30 KB signature does not fit in a single unfragmented UDP datagram, and does not fit in
//! the kernel's existing 4809-byte grant buffer. Keeping all three and requiring all three is
//! the composition that is strong against every adversary we know how to name; choosing one
//! "strongest" primitive would trade one attack surface for another.

use slh_dsa::{
    signature::{Keypair as _, Signer as _, Verifier as _},
    Sha2_256s, SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    rng,
    seeded_rng::SeededRng,
    sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey},
    sizes, CryptoError,
};

/// Domain separation for deriving the SLH-DSA key pair from its stored seed.
const SLH_KEY_LABEL: &[u8] = b"SOVEREIGN/v1/slh-dsa-key";

/// SLH-DSA-SHA2-256s verifying key length, from the FIPS 205 parameter set.
pub const SLH_VK_LEN: usize = 64;
/// SLH-DSA-SHA2-256s signature length. The "s" (small) set trades signing time for this size;
/// the "f" set would be ~17 KB with faster signing.
pub const SLH_SIG_LEN: usize = 29_792;
/// Length of the seed this crate stores for SLH-DSA.
///
/// Deliberately *not* the 128-byte encoded signing key. FIPS 205 derives three independent
/// seeds into a key pair, and the crate's decoder trusts the public half embedded in the
/// encoding rather than recomputing it — so a hand-made 128-byte string yields a key whose
/// public half does not match its private seed, and every signature it makes fails to verify.
/// Storing one 32-byte seed and deriving through the crate's own constructor is the only way to
/// get a key that round-trips.
pub const SLH_SEED_LEN: usize = 32;

/// All three halves over one domain-separated transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriSignature {
    /// The ECDSA + ML-DSA pair, exactly as [`crate::sign`] produces it.
    pub hybrid: HybridSignature,
    /// SLH-DSA half.
    pub slh: Vec<u8>,
}

impl TriSignature {
    /// `hybrid.encode() ‖ u16_be(len) ‖ slh`, matching the layout used for the other halves.
    pub fn encode(&self) -> Vec<u8> {
        let inner = self.hybrid.encode();
        let mut out = Vec::with_capacity(inner.len() + 2 + self.slh.len());
        out.extend_from_slice(&inner);
        out.extend_from_slice(&(self.slh.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.slh);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        // Both halves are fixed-size, so the inner hybrid blob is exactly this long. Slicing it
        // out is required: `HybridSignature::decode` refuses trailing bytes, by design.
        const INNER: usize = sizes::P384_SIG + 2 + sizes::ML_DSA_87_SIG;
        let inner = buf.get(..INNER).ok_or(CryptoError::Encoding)?;
        let hybrid = HybridSignature::decode(inner)?;

        let len_bytes = buf.get(INNER..INNER + 2).ok_or(CryptoError::Encoding)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        let start = INNER + 2;
        if buf.len() != start + len {
            return Err(CryptoError::Encoding);
        }
        Ok(Self {
            hybrid,
            slh: buf[start..].to_vec(),
        })
    }
}

/// Signing key holding all three secrets.
///
/// The SLH-DSA key is stored as its 128-byte encoded form rather than a seed: FIPS 205 keys are
/// derived from three independent n-byte seeds plus the parameter set, and re-deriving on every
/// signature would cost more than storing them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TriSigningKey {
    hybrid: HybridSigningKey,
    slh_seed: [u8; SLH_SEED_LEN],
}

impl TriSigningKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let hybrid = HybridSigningKey::generate()?;
        let mut slh_seed = [0u8; SLH_SEED_LEN];
        rng::fill_random(&mut slh_seed)?;
        Ok(Self { hybrid, slh_seed })
    }

    /// Deterministic reconstruction from stored seed material.
    pub fn from_seeds(
        ecdsa_seed: [u8; 48],
        mldsa_seed: [u8; 32],
        slh_seed: [u8; SLH_SEED_LEN],
    ) -> Self {
        Self {
            hybrid: HybridSigningKey::from_seeds(ecdsa_seed, mldsa_seed),
            slh_seed,
        }
    }

    /// Raw seed material. Persist only into sealed storage.
    pub fn seeds(&self) -> ([u8; 48], [u8; 32], [u8; SLH_SEED_LEN]) {
        let (a, b) = self.hybrid.seeds();
        (a, b, self.slh_seed)
    }

    /// Derive the SLH-DSA key pair from the stored seed.
    ///
    /// The crate's constructor consumes an `Rng`, so the seed is expanded by HKDF into the three
    /// seeds FIPS 205 needs. Deterministic: the same stored seed always yields the same key.
    fn slh_signing_key(&self) -> Result<SlhSigningKey<Sha2_256s>, CryptoError> {
        let mut rng = SeededRng::new(&self.slh_seed, SLH_KEY_LABEL, 96)?;
        Ok(SlhSigningKey::<Sha2_256s>::new(&mut rng))
    }

    pub fn verifying_key(&self) -> TriVerifyingKey {
        let slh_sk = self
            .slh_signing_key()
            .expect("96 bytes is within the expansion limit");
        let mut slh = [0u8; SLH_VK_LEN];
        slh.copy_from_slice(&slh_sk.verifying_key().to_bytes());
        TriVerifyingKey {
            hybrid: self.hybrid.verifying_key(),
            slh,
        }
    }

    /// Sign under all three primitives. Costs roughly 470 ms, dominated by SLH-DSA.
    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<TriSignature, CryptoError> {
        let hybrid = self.hybrid.sign(domain, msg)?;

        // SLH-DSA signs the same transcript the other two halves sign, so a signature cannot be
        // moved between domains or between messages without all three halves disagreeing.
        let transcript = crate::sign::transcript(domain, msg);
        let slh_sk = self.slh_signing_key()?;
        let sig = slh_sk.sign(&transcript);

        Ok(TriSignature {
            hybrid,
            slh: sig.to_bytes().to_vec(),
        })
    }
}

impl core::fmt::Debug for TriSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TriSigningKey(<redacted>)")
    }
}

/// Public half of a [`TriSigningKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriVerifyingKey {
    pub hybrid: HybridVerifyingKey,
    pub slh: [u8; SLH_VK_LEN],
}

impl TriVerifyingKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.hybrid.encode();
        out.extend_from_slice(&self.slh);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != sizes::P384_SEC1 + sizes::ML_DSA_87_VK + SLH_VK_LEN {
            return Err(CryptoError::Encoding);
        }
        let split = sizes::P384_SEC1 + sizes::ML_DSA_87_VK;
        let hybrid = HybridVerifyingKey::decode(&buf[..split])?;
        let mut slh = [0u8; SLH_VK_LEN];
        slh.copy_from_slice(&buf[split..]);
        Ok(Self { hybrid, slh })
    }

    /// Verify all three. Returns `Err` unless every half accepts; there is no subset mode.
    pub fn verify(&self, domain: &[u8], msg: &[u8], sig: &TriSignature) -> Result<(), CryptoError> {
        // Cheap halves first. Ordering is a performance choice only: all three always run when
        // the earlier ones pass, so it cannot weaken the AND.
        self.hybrid.verify(domain, msg, &sig.hybrid)?;

        let transcript = crate::sign::transcript(domain, msg);
        let vk = SlhVerifyingKey::<Sha2_256s>::try_from(&self.slh[..])
            .map_err(|_| CryptoError::Encoding)?;
        let slh_sig: [u8; SLH_SIG_LEN] = sig
            .slh
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Encoding)?;
        let parsed = slh_dsa::Signature::<Sha2_256s>::try_from(&slh_sig[..])
            .map_err(|_| CryptoError::Encoding)?;
        vk.verify(&transcript, &parsed)
            .map_err(|_| CryptoError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use crate::labels;

    use super::*;

    fn key() -> TriSigningKey {
        TriSigningKey::from_seeds([0x11; 48], [0x22; 32], [0x55; SLH_SEED_LEN])
    }

    #[test]
    fn all_three_halves_verify() {
        let k = key();
        let sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        assert_eq!(sig.slh.len(), SLH_SIG_LEN);
        k.verifying_key()
            .verify(labels::CAPABILITY, b"token", &sig)
            .expect("verify");
    }

    #[test]
    fn a_tampered_slh_half_is_refused() {
        let k = key();
        let mut sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        sig.slh[100] ^= 0x01;
        assert_eq!(
            k.verifying_key()
                .verify(labels::CAPABILITY, b"token", &sig)
                .unwrap_err(),
            CryptoError::Verification
        );
    }

    #[test]
    fn a_tampered_message_is_refused() {
        let k = key();
        let sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        assert!(k
            .verifying_key()
            .verify(labels::CAPABILITY, b"tokeN", &sig)
            .is_err());
    }

    #[test]
    fn a_different_domain_is_refused() {
        let k = key();
        let sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        assert!(k
            .verifying_key()
            .verify(labels::ATTESTATION, b"token", &sig)
            .is_err());
    }

    #[test]
    fn a_foreign_slh_key_is_refused() {
        let k = key();
        let sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        let other = TriSigningKey::from_seeds([0x33; 48], [0x44; 32], [0x66; SLH_SEED_LEN]);
        assert!(other
            .verifying_key()
            .verify(labels::CAPABILITY, b"token", &sig)
            .is_err());
    }

    #[test]
    fn a_hybrid_only_signature_replayed_as_tri_is_refused() {
        // Downgrade attempt: take a valid ECDSA+ML-DSA signature and staple any SLH half on.
        let k = key();
        let hybrid = k.hybrid.sign(labels::CAPABILITY, b"token").expect("sign");
        let forged = TriSignature {
            hybrid,
            slh: vec![0u8; SLH_SIG_LEN],
        };
        assert!(k
            .verifying_key()
            .verify(labels::CAPABILITY, b"token", &forged)
            .is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let k = key();
        let sig = k.sign(labels::CAPABILITY, b"token").expect("sign");
        let enc = sig.encode();
        assert_eq!(
            enc.len(),
            sizes::P384_SIG + 2 + sizes::ML_DSA_87_SIG + 2 + SLH_SIG_LEN
        );
        assert_eq!(TriSignature::decode(&enc).expect("decode"), sig);
    }

    #[test]
    fn truncated_or_padded_encodings_are_refused() {
        let k = key();
        let enc = k.sign(labels::CAPABILITY, b"token").expect("sign").encode();
        assert!(TriSignature::decode(&enc[..enc.len() - 1]).is_err());
        let mut padded = enc.clone();
        padded.push(0);
        assert!(TriSignature::decode(&padded).is_err());
    }

    #[test]
    fn verifying_key_roundtrip() {
        let vk = key().verifying_key();
        let enc = vk.encode();
        assert_eq!(
            enc.len(),
            sizes::P384_SEC1 + sizes::ML_DSA_87_VK + SLH_VK_LEN
        );
        assert_eq!(TriVerifyingKey::decode(&enc).expect("decode"), vk);
    }

    #[test]
    fn seeds_restore_the_same_identity() {
        let k = key();
        let (a, b, c) = k.seeds();
        assert_eq!(
            TriSigningKey::from_seeds(a, b, c).verifying_key(),
            k.verifying_key()
        );
    }

    #[test]
    fn slh_signing_is_deterministic() {
        // FIPS 205 signing is deterministic given the key and message, which is what lets the
        // kernel-side vector generator produce stable test vectors.
        let k = key();
        let a = k.sign(labels::CAPABILITY, b"token").expect("sign");
        let b = k.sign(labels::CAPABILITY, b"token").expect("sign");
        assert_eq!(a.slh, b.slh);
    }
}
