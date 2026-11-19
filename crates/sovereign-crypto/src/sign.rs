//! Hybrid signatures: ECDSA P-384 **and** ML-DSA-87, both required.
//!
//! The message is domain-separated and length-prefixed so that a signature over `("ab", "c")`
//! can never be confused with one over `("a", "bc")`. Without the length prefix, a caller that
//! concatenates variable-length fields reintroduces a classic signature-splicing attack.

use ml_dsa::{
    signature::{Keypair as _, Signer as _, Verifier as _},
    KeyInit as _, MlDsa87, Signature as MlDsaSignature, SigningKey, VerifyingKey,
};
use p384::{
    ecdsa::{
        Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    SecretKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{labels, rng, sizes, CryptoError};

/// A hybrid signature: classical half plus post-quantum half, both over the same message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Fixed-size ECDSA P-384 signature, `r || s`.
    pub ecdsa: [u8; sizes::P384_SIG],
    /// ML-DSA-87 signature bytes.
    pub mldsa: Vec<u8>,
}

impl HybridSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(sizes::P384_SIG + 2 + self.mldsa.len());
        out.extend_from_slice(&self.ecdsa);
        out.extend_from_slice(&(self.mldsa.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() < sizes::P384_SIG + 2 {
            return Err(CryptoError::Encoding);
        }
        let mut ecdsa = [0u8; sizes::P384_SIG];
        ecdsa.copy_from_slice(&buf[..sizes::P384_SIG]);
        let len = u16::from_be_bytes([buf[sizes::P384_SIG], buf[sizes::P384_SIG + 1]]) as usize;
        let start = sizes::P384_SIG + 2;
        if buf.len() != start + len {
            return Err(CryptoError::Encoding);
        }
        Ok(Self {
            ecdsa,
            mldsa: buf[start..].to_vec(),
        })
    }
}

/// The root (or device) signing key: one classical key and one post-quantum key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSigningKey {
    ecdsa_seed: [u8; 48],
    mldsa_seed: [u8; 32],
}

impl HybridSigningKey {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut ecdsa_seed = [0u8; 48];
        let mut mldsa_seed = [0u8; 32];
        rng::fill_random(&mut ecdsa_seed)?;
        rng::fill_random(&mut mldsa_seed)?;
        Ok(Self {
            ecdsa_seed,
            mldsa_seed,
        })
    }

    /// Deterministic reconstruction from stored seed material. Callers are responsible for
    /// keeping `ecdsa_seed`/`mldsa_seed` inside an HSM, TPM, or sealed storage.
    pub fn from_seeds(ecdsa_seed: [u8; 48], mldsa_seed: [u8; 32]) -> Self {
        Self {
            ecdsa_seed,
            mldsa_seed,
        }
    }

    /// Raw seed material, for persisting into sealed storage only.
    pub fn seeds(&self) -> ([u8; 48], [u8; 32]) {
        (self.ecdsa_seed, self.mldsa_seed)
    }

    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let sk = self.ecdsa_signing_key();
        let vk = sk.verifying_key();
        let point = vk.to_sec1_point(false);
        let mut ecdsa_pub = [0u8; sizes::P384_SEC1];
        ecdsa_pub.copy_from_slice(point.as_bytes());

        let pq = SigningKey::<MlDsa87>::from_seed(&self.mldsa_seed.into());
        let pq_vk = pq.verifying_key().encode();

        HybridVerifyingKey {
            ecdsa: ecdsa_pub,
            mldsa: pq_vk.to_vec(),
        }
    }

    fn ecdsa_signing_key(&self) -> EcdsaSigningKey {
        let secret = SecretKey::from_slice(&self.ecdsa_seed).expect("48-byte scalar is in range");
        EcdsaSigningKey::from(secret)
    }

    /// Sign `msg` with both primitives under a domain-separated, length-prefixed transcript.
    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<HybridSignature, CryptoError> {
        let transcript = transcript(domain, msg);

        let ecdsa_sig: EcdsaSignature = self.ecdsa_signing_key().sign(&transcript);
        let mut ecdsa = [0u8; sizes::P384_SIG];
        ecdsa.copy_from_slice(&ecdsa_sig.to_bytes());

        let pq_key = SigningKey::<MlDsa87>::from_seed(&self.mldsa_seed.into());
        let pq_sig: MlDsaSignature<MlDsa87> = pq_key
            .try_sign(&transcript)
            .map_err(|_| CryptoError::Verification)?;

        Ok(HybridSignature {
            ecdsa,
            mldsa: pq_sig.encode().to_vec(),
        })
    }
}

impl core::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material, even accidentally, into a log line.
        f.write_str("HybridSigningKey(<redacted>)")
    }
}

/// Public half of a [`HybridSigningKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    /// Uncompressed SEC1 P-384 point, 97 bytes.
    pub ecdsa: [u8; sizes::P384_SEC1],
    /// Encoded ML-DSA-87 verifying key.
    pub mldsa: Vec<u8>,
}

impl HybridVerifyingKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(sizes::P384_SEC1 + self.mldsa.len());
        out.extend_from_slice(&self.ecdsa);
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != sizes::P384_SEC1 + sizes::ML_DSA_87_VK {
            return Err(CryptoError::Encoding);
        }
        let mut ecdsa = [0u8; sizes::P384_SEC1];
        ecdsa.copy_from_slice(&buf[..sizes::P384_SEC1]);
        Ok(Self {
            ecdsa,
            mldsa: buf[sizes::P384_SEC1..].to_vec(),
        })
    }

    /// A stable identifier for this key, safe to log and to use as a key id.
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"SOVEREIGN/v1/key-fingerprint");
        h.update(self.ecdsa);
        h.update(&self.mldsa);
        h.finalize().into()
    }

    /// Verify **both** halves. Short-circuits to `Err` if either fails; there is no mode in
    /// which a single valid half is accepted.
    pub fn verify(
        &self,
        domain: &[u8],
        msg: &[u8],
        sig: &HybridSignature,
    ) -> Result<(), CryptoError> {
        let transcript = transcript(domain, msg);

        let ecdsa_vk =
            EcdsaVerifyingKey::from_sec1_bytes(&self.ecdsa).map_err(|_| CryptoError::Encoding)?;
        let ecdsa_sig =
            EcdsaSignature::from_slice(&sig.ecdsa).map_err(|_| CryptoError::Encoding)?;
        ecdsa_vk
            .verify(&transcript, &ecdsa_sig)
            .map_err(|_| CryptoError::Verification)?;

        let pq_vk_bytes: [u8; sizes::ML_DSA_87_VK] = self
            .mldsa
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Encoding)?;
        let pq_vk = VerifyingKey::<MlDsa87>::new(&pq_vk_bytes.into());
        let pq_sig = MlDsaSignature::<MlDsa87>::try_from(sig.mldsa.as_slice())
            .map_err(|_| CryptoError::Verification)?;
        pq_vk
            .verify(&transcript, &pq_sig)
            .map_err(|_| CryptoError::Verification)?;

        Ok(())
    }
}

/// Build the signed transcript: domain tag, then each part length-prefixed.
fn transcript(domain: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(labels::SIGN.len() + 8 + domain.len() + msg.len());
    t.extend_from_slice(labels::SIGN);
    t.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    t.extend_from_slice(domain);
    t.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    t.extend_from_slice(msg);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 204 ML-DSA-87 and FIPS 186-5 P-384 sizes. If these drift, we are no longer
    /// producing the algorithm we claim to produce.
    #[test]
    fn output_sizes_match_nist_parameters() {
        let sk = HybridSigningKey::generate().expect("generate");
        let vk = sk.verifying_key();
        let sig = sk.sign(b"dom", b"msg").expect("sign");

        assert_eq!(sig.mldsa.len(), sizes::ML_DSA_87_SIG);
        assert_eq!(sig.ecdsa.len(), sizes::P384_SIG);
        assert_eq!(vk.mldsa.len(), sizes::ML_DSA_87_VK);
        assert_eq!(vk.ecdsa.len(), sizes::P384_SEC1);
        assert_eq!(sig.mldsa.len(), 4627, "ML-DSA-87 signature");
        assert_eq!(sig.ecdsa.len(), 96, "P-384 signature");
    }

    fn key() -> HybridSigningKey {
        HybridSigningKey::generate().expect("entropy")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"capability", b"payload").expect("sign");
        vk.verify(b"capability", b"payload", &sig).expect("verify");
    }

    #[test]
    fn wrong_domain_fails() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"capability", b"payload").expect("sign");
        assert_eq!(
            vk.verify(b"attestation", b"payload", &sig).unwrap_err(),
            CryptoError::Verification
        );
    }

    #[test]
    fn tampered_message_fails() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"capability", b"payload").expect("sign");
        assert_eq!(
            vk.verify(b"capability", b"payloaD", &sig).unwrap_err(),
            CryptoError::Verification
        );
    }

    /// The critical property: breaking only one primitive must not be enough. We simulate the
    /// classical half being forged by replacing it with a valid signature from another key.
    #[test]
    fn both_halves_are_required() {
        let sk = key();
        let other = key();
        let vk = sk.verifying_key();

        let mut sig = sk.sign(b"capability", b"payload").expect("sign");
        let foreign = other.sign(b"capability", b"payload").expect("sign");
        sig.ecdsa = foreign.ecdsa;

        assert_eq!(
            vk.verify(b"capability", b"payload", &sig).unwrap_err(),
            CryptoError::Verification
        );

        // And the reverse: a valid classical half with a foreign PQ half.
        let mut sig2 = sk.sign(b"capability", b"payload").expect("sign");
        sig2.mldsa = foreign.mldsa;
        assert_eq!(
            vk.verify(b"capability", b"payload", &sig2).unwrap_err(),
            CryptoError::Verification
        );
    }

    #[test]
    fn signature_encoding_roundtrip() {
        let sk = key();
        let sig = sk.sign(b"capability", b"payload").expect("sign");
        let enc = sig.encode();
        assert_eq!(HybridSignature::decode(&enc).expect("decode"), sig);
    }

    #[test]
    fn signature_encoding_rejects_truncation_and_padding() {
        let sk = key();
        let sig = sk.sign(b"capability", b"payload").expect("sign");
        let enc = sig.encode();

        assert_eq!(
            HybridSignature::decode(&enc[..enc.len() - 1]).unwrap_err(),
            CryptoError::Encoding
        );

        let mut padded = enc.clone();
        padded.push(0);
        assert_eq!(
            HybridSignature::decode(&padded).unwrap_err(),
            CryptoError::Encoding
        );
    }

    #[test]
    fn verifying_key_roundtrip_and_fingerprint_stability() {
        let sk = key();
        let vk = sk.verifying_key();
        let enc = vk.encode();
        assert_eq!(enc.len(), sizes::P384_SEC1 + sizes::ML_DSA_87_VK);
        let decoded = HybridVerifyingKey::decode(&enc).expect("decode");
        assert_eq!(decoded, vk);
        assert_eq!(decoded.fingerprint(), vk.fingerprint());
    }

    #[test]
    fn transcript_is_unambiguous() {
        assert_ne!(transcript(b"ab", b"c"), transcript(b"a", b"bc"));
    }

    #[test]
    fn seeds_roundtrip_deterministically() {
        let sk = key();
        let (a, b) = sk.seeds();
        let restored = HybridSigningKey::from_seeds(a, b);
        assert_eq!(restored.verifying_key(), sk.verifying_key());
    }
}
