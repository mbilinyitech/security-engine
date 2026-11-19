use crate::CryptoError;

/// Fill `dst` from the OS CSPRNG.
///
/// There is no fallback path on purpose. A system that silently degrades to a userspace PRNG
/// when `getrandom` fails is worse than one that refuses to start: it produces keys that look
/// fine and are guessable.
pub fn fill_random(dst: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dst).map_err(|_| CryptoError::Entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_does_not_repeat() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).expect("entropy");
        fill_random(&mut b).expect("entropy");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
