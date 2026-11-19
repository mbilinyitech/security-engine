//! Hybrid key encapsulation: ML-KEM-1024 **and** ECDH P-384, combined through HKDF-SHA-384.
//!
//! Combining two KEM secrets by concatenation and hashing is only safe if the combiner is
//! unambiguous. We feed both shared secrets into HKDF as IKM with a fixed, length-prefixed
//! `info` string, and additionally bind both public keys into the transcript. That way a
//! malicious peer cannot swap in its own key for one half and leave the other untouched
//! (the "KEM key-mix" attack).

use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate as _, Encapsulate as _},
    KeyExport as _, MlKem1024,
};
use p384::{
    elliptic_curve::{sec1::ToSec1Point as _, PublicKey},
    SecretKey,
};
use sha2::Sha384;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{labels, rng, sizes, CryptoError};

/// A recipient's public material: one ML-KEM encapsulation key plus one P-384 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPublicKey {
    pub mlkem: [u8; sizes::ML_KEM_1024_EK],
    pub ecdh: [u8; sizes::P384_SEC1],
}

impl RecipientPublicKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.mlkem.len() + self.ecdh.len());
        out.extend_from_slice(&self.mlkem);
        out.extend_from_slice(&self.ecdh);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != sizes::ML_KEM_1024_EK + sizes::P384_SEC1 {
            return Err(CryptoError::Encoding);
        }
        let mut mlkem = [0u8; sizes::ML_KEM_1024_EK];
        let mut ecdh = [0u8; sizes::P384_SEC1];
        mlkem.copy_from_slice(&buf[..sizes::ML_KEM_1024_EK]);
        ecdh.copy_from_slice(&buf[sizes::ML_KEM_1024_EK..]);
        Ok(Self { mlkem, ecdh })
    }
}

/// The ciphertext half of an encapsulation: ML-KEM ciphertext plus an ephemeral P-384 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridCiphertext {
    pub mlkem: [u8; sizes::ML_KEM_1024_CT],
    pub eph: [u8; sizes::P384_SEC1],
}

impl HybridCiphertext {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.mlkem.len() + self.eph.len());
        out.extend_from_slice(&self.mlkem);
        out.extend_from_slice(&self.eph);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != sizes::ML_KEM_1024_CT + sizes::P384_SEC1 {
            return Err(CryptoError::Encoding);
        }
        let mut mlkem = [0u8; sizes::ML_KEM_1024_CT];
        let mut eph = [0u8; sizes::P384_SEC1];
        mlkem.copy_from_slice(&buf[..sizes::ML_KEM_1024_CT]);
        eph.copy_from_slice(&buf[sizes::ML_KEM_1024_CT..]);
        Ok(Self { mlkem, eph })
    }
}

/// A recipient key pair. The decapsulation key is seed-only so it zeroizes cleanly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemKeyPair {
    mlkem_seed: [u8; 64],
    ecdh_scalar: [u8; 48],
    #[zeroize(skip)]
    public: RecipientPublicKey,
}

impl KemKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut mlkem_seed = [0u8; 64];
        let mut ecdh_scalar = [0u8; 48];
        rng::fill_random(&mut mlkem_seed)?;
        rng::fill_random(&mut ecdh_scalar)?;
        Self::from_seeds(mlkem_seed, ecdh_scalar)
    }

    pub fn from_seeds(mlkem_seed: [u8; 64], ecdh_scalar: [u8; 48]) -> Result<Self, CryptoError> {
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(mlkem_seed.into());
        let ek = dk.encapsulation_key().to_bytes();

        let secret = SecretKey::from_slice(&ecdh_scalar).map_err(|_| CryptoError::Encoding)?;
        let point = secret.public_key().to_sec1_point(false);

        let mut mlkem = [0u8; sizes::ML_KEM_1024_EK];
        mlkem.copy_from_slice(&ek);
        let mut ecdh = [0u8; sizes::P384_SEC1];
        ecdh.copy_from_slice(point.as_bytes());

        Ok(Self {
            mlkem_seed,
            ecdh_scalar,
            public: RecipientPublicKey { mlkem, ecdh },
        })
    }

    pub fn public(&self) -> &RecipientPublicKey {
        &self.public
    }

    /// Encapsulate to `recipient`, producing a ciphertext and the derived 32-byte key.
    pub fn encapsulate_to(
        recipient: &RecipientPublicKey,
    ) -> Result<(HybridCiphertext, [u8; 32]), CryptoError> {
        let ek = ml_kem::EncapsulationKey::<MlKem1024>::new(&recipient.mlkem.into())
            .map_err(|_| CryptoError::Encoding)?;
        let (ct, ss_pq) = ek.encapsulate();

        let peer =
            PublicKey::from_sec1_bytes(&recipient.ecdh).map_err(|_| CryptoError::Encoding)?;

        let mut scalar = [0u8; 48];
        rng::fill_random(&mut scalar)?;
        let eph_secret = SecretKey::from_slice(&scalar).map_err(|_| CryptoError::Encoding)?;
        let eph_public = eph_secret.public_key().to_sec1_point(false);
        let ss_ec = eph_secret.diffie_hellman(&peer);

        let mut mlkem = [0u8; sizes::ML_KEM_1024_CT];
        mlkem.copy_from_slice(&ct);
        let mut eph = [0u8; sizes::P384_SEC1];
        eph.copy_from_slice(eph_public.as_bytes());

        let key = combine(
            ss_pq.as_slice(),
            ss_ec.raw_secret_bytes().as_slice(),
            recipient,
            &eph,
        );
        Ok((HybridCiphertext { mlkem, eph }, key))
    }

    /// Decapsulate a ciphertext addressed to this key pair.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<[u8; 32], CryptoError> {
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(self.mlkem_seed.into());
        let mlkem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct.mlkem.as_slice())
            .map_err(|_| CryptoError::Encoding)?;
        let ss_pq = dk.decapsulate(&mlkem_ct);

        let eph = PublicKey::from_sec1_bytes(&ct.eph).map_err(|_| CryptoError::Encoding)?;
        let secret = SecretKey::from_slice(&self.ecdh_scalar).map_err(|_| CryptoError::Encoding)?;
        let ss_ec = secret.diffie_hellman(&eph);

        Ok(combine(
            ss_pq.as_slice(),
            ss_ec.raw_secret_bytes().as_slice(),
            &self.public,
            &ct.eph,
        ))
    }
}

impl core::fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemKeyPair(<redacted>)")
    }
}

/// HKDF-SHA-384 over both shared secrets, bound to both public keys.
fn combine(
    ss_pq: &[u8],
    ss_ec: &[u8],
    recipient: &RecipientPublicKey,
    eph: &[u8; sizes::P384_SEC1],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_pq.len() + ss_ec.len());
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_ec);

    let mut info = Vec::with_capacity(64 + recipient.mlkem.len() + recipient.ecdh.len());
    info.extend_from_slice(labels::KEM);
    info.extend_from_slice(&(ss_pq.len() as u32).to_be_bytes());
    info.extend_from_slice(&(ss_ec.len() as u32).to_be_bytes());
    info.extend_from_slice(&recipient.mlkem);
    info.extend_from_slice(&recipient.ecdh);
    info.extend_from_slice(eph);

    let hk = Hkdf::<Sha384>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is far below the HKDF-SHA-384 output limit");

    ikm.zeroize();
    info.zeroize();
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_agree() {
        let kp = KemKeyPair::generate().expect("entropy");
        let (ct, key_a) = KemKeyPair::encapsulate_to(kp.public()).expect("encap");
        let key_b = kp.decapsulate(&ct).expect("decap");
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn different_sessions_derive_different_keys() {
        let kp = KemKeyPair::generate().expect("entropy");
        let (_, k1) = KemKeyPair::encapsulate_to(kp.public()).expect("encap");
        let (_, k2) = KemKeyPair::encapsulate_to(kp.public()).expect("encap");
        assert_ne!(k1, k2);
    }

    #[test]
    fn wrong_recipient_cannot_decapsulate_to_same_key() {
        let a = KemKeyPair::generate().expect("entropy");
        let b = KemKeyPair::generate().expect("entropy");
        let (ct, key_a) = KemKeyPair::encapsulate_to(a.public()).expect("encap");
        let key_b = b.decapsulate(&ct).expect("decap must not panic");
        assert_ne!(key_a, key_b);
    }

    /// Swapping the ephemeral point for another valid point must change the derived key,
    /// because the point is bound into the HKDF info.
    #[test]
    fn ephemeral_point_is_bound_into_derivation() {
        let kp = KemKeyPair::generate().expect("entropy");
        let other = KemKeyPair::generate().expect("entropy");
        let (mut ct, key_a) = KemKeyPair::encapsulate_to(kp.public()).expect("encap");
        ct.eph = other.public().ecdh;
        let key_b = kp.decapsulate(&ct).expect("decap");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn ciphertext_encoding_roundtrip() {
        let kp = KemKeyPair::generate().expect("entropy");
        let (ct, _) = KemKeyPair::encapsulate_to(kp.public()).expect("encap");
        let enc = ct.encode();
        assert_eq!(HybridCiphertext::decode(&enc).expect("decode"), ct);
        assert_eq!(
            HybridCiphertext::decode(&enc[..enc.len() - 1]).unwrap_err(),
            CryptoError::Encoding
        );
    }

    #[test]
    fn public_key_encoding_roundtrip() {
        let kp = KemKeyPair::generate().expect("entropy");
        let enc = kp.public().encode();
        assert_eq!(
            RecipientPublicKey::decode(&enc).expect("decode"),
            *kp.public()
        );
    }

    #[test]
    fn seeds_are_deterministic() {
        let kp = KemKeyPair::generate().expect("entropy");
        let restored = KemKeyPair::from_seeds(kp.mlkem_seed, kp.ecdh_scalar).expect("restore");
        assert_eq!(restored.public(), kp.public());
    }
}
