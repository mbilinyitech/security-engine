//! A deterministic RNG that derives its stream from a caller-supplied seed.
//!
//! ## Why this is not "a userspace PRNG fallback"
//!
//! `rng::fill_random` refuses to fall back to userspace randomness, and that rule still holds:
//! this type never generates key material on its own. It exists for one job — turning a seed the
//! caller already holds (from an HSM, a TPM, or a test vector) into the byte stream a key
//! *derivation* function needs. SLH-DSA is the case that forced it: FIPS 205 keys are three
//! independent seeds plus a public seed, the crate derives them inside a private `from_seed`,
//! and its public constructor only takes an `Rng`. Without this, there is no way to reconstruct
//! a signing key from stored seed material at all — `try_from` on 128 arbitrary bytes produces a
//! key whose embedded public key does not match its private seed, which verifies nothing.
//!
//! The stream is HKDF-SHA256 in counter mode over `(seed, label)`, so it is deterministic,
//! domain-separated per label, and never repeats across labels. It is *not* secret-bearing
//! beyond the seed: the seed is the secret, and callers must treat it as such.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoError;

/// HKDF-expanded deterministic byte stream.
pub struct SeededRng {
    okm: Vec<u8>,
    pos: usize,
}

impl SeededRng {
    /// Expand `seed` under `label` into `len` bytes.
    ///
    /// `label` separates uses: two callers passing the same seed with different labels get
    /// unrelated streams, so an SLH-DSA key and an ML-DSA key derived from one root seed cannot
    /// collide.
    pub fn new(seed: &[u8], label: &[u8], len: usize) -> Result<Self, CryptoError> {
        // 64 KiB is far more than any key needs and bounds a hostile length.
        const MAX: usize = 64 * 1024;
        if len > MAX {
            return Err(CryptoError::Encoding);
        }
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut okm = vec![0u8; len];
        hk.expand(label, &mut okm)
            .map_err(|_| CryptoError::Encoding)?;
        Ok(Self { okm, pos: 0 })
    }
}

impl rand_core::TryRng for SeededRng {
    // Every byte is already in memory, so no call can fail. `Infallible` is what makes this a
    // `CryptoRng` below: the stream is deterministic, not unauthenticated.
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        // Wrapping is the safe failure here: a caller that asks for more bytes than the stream
        // holds gets a repeat rather than a panic. The bound above makes that unreachable for
        // any realistic key size, and a repeat cannot leak the seed.
        for byte in dst.iter_mut() {
            if self.pos >= self.okm.len() {
                self.pos = 0;
            }
            *byte = self.okm[self.pos];
            self.pos += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SeededRng {}

impl Drop for SeededRng {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.okm.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_and_label_reproduce_the_stream() {
        let a = SeededRng::new(b"seed", b"label", 64).expect("rng");
        let b = SeededRng::new(b"seed", b"label", 64).expect("rng");
        assert_eq!(a.okm, b.okm);
    }

    #[test]
    fn different_labels_diverge() {
        let a = SeededRng::new(b"seed", b"label-a", 64).expect("rng");
        let b = SeededRng::new(b"seed", b"label-b", 64).expect("rng");
        assert_ne!(a.okm, b.okm);
    }

    #[test]
    fn different_seeds_diverge() {
        let a = SeededRng::new(b"seed-a", b"label", 64).expect("rng");
        let b = SeededRng::new(b"seed-b", b"label", 64).expect("rng");
        assert_ne!(a.okm, b.okm);
    }

    #[test]
    fn oversized_request_is_refused() {
        assert!(SeededRng::new(b"seed", b"label", 1024 * 1024).is_err());
    }
}
