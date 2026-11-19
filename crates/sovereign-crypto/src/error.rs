use core::fmt;

/// Errors from the hybrid crypto engine.
///
/// Deliberately coarse: the caller learns *that* a primitive failed, never *why*. Distinguishing
/// "wrong key" from "bad encoding" from "invalid point" gives an attacker a padding-oracle-like
/// side channel, so all verification failures collapse into [`CryptoError::Verification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A signature, MAC, or KEM ciphertext failed to authenticate.
    Verification,
    /// Key or ciphertext bytes had the wrong length or were malformed.
    Encoding,
    /// The AEAD refused the ciphertext (wrong key, tampered header, or truncated input).
    Decrypt,
    /// A counter was at or below the replay window's high-water mark.
    Replay,
    /// The OS random source failed. Never fall back to a userspace PRNG.
    Entropy,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification => write!(f, "verification failed"),
            Self::Encoding => write!(f, "malformed key or ciphertext encoding"),
            Self::Decrypt => write!(f, "decryption failed"),
            Self::Replay => write!(f, "replayed counter"),
            Self::Entropy => write!(f, "system entropy unavailable"),
        }
    }
}

impl std::error::Error for CryptoError {}
