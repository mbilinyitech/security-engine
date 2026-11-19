//! Emit a complete hybrid grant vector for the kernel-side verifier.
//!
//! The kernel builds its own transcript and verifies both halves. This emits the exact bytes
//! it must accept, and the tampered variants it must reject, so the VM tests are checking a
//! signature made by the real signer rather than a fixture that agrees only with itself.
//!
//! Run with: cargo test -p sovereign-crypto --test hybrid_kernel_vectors -- --nocapture

use sovereign_crypto::{labels, HybridSigningKey};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn emit_hybrid_kernel_vectors() {
    // Fixed seeds: the kernel selftest embeds these bytes, so they must be reproducible.
    let sk = HybridSigningKey::from_seeds([0x11; 48], [0x22; 32]);
    let vk = sk.verifying_key();

    let domain = labels::SIGN;
    let msg = b"sovereign kernel hybrid grant test message";

    let sig = sk.sign(domain, msg).expect("sign");

    println!("DOMAIN={}", hex(domain));
    println!("MSG={}", hex(msg));
    println!("ECDSA_PUB={}", hex(&vk.ecdsa));
    println!("MLDSA_VK={}", hex(&vk.mldsa));
    println!("ECDSA_SIG={}", hex(&sig.ecdsa));
    println!("MLDSA_SIG={}", hex(&sig.mldsa));

    // Tampered variants the kernel must refuse.
    let mut bad_ecdsa = sig.ecdsa;
    bad_ecdsa[10] ^= 0x01;
    println!("BAD_ECDSA_SIG={}", hex(&bad_ecdsa));

    let mut bad_mldsa = sig.mldsa.clone();
    // Flip inside c_tilde (byte 32), the same spot the ML-DSA selftest targets.
    bad_mldsa[32] ^= 0x01;
    println!("BAD_MLDSA_SIG={}", hex(&bad_mldsa));

    // A second key: its signature must not verify against the first key's public halves.
    let other = HybridSigningKey::from_seeds([0x33; 48], [0x44; 32]);
    let foreign = other.sign(domain, msg).expect("sign");
    println!("FOREIGN_ECDSA_SIG={}", hex(&foreign.ecdsa));
    println!("FOREIGN_MLDSA_SIG={}", hex(&foreign.mldsa));

    // Cross-pairing: ECDSA from `sk`, ML-DSA from `other`. Both halves are individually
    // valid over the same transcript, but by different signers. The kernel must reject this
    // because each half is checked against the same public key pair.
    println!("FOREIGN_ECDSA_PUB={}", hex(&other.verifying_key().ecdsa));
}
