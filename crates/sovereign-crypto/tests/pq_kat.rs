//! Emit ML-DSA-87 known-answer vectors as hex, so a C verifier can be tested against the same
//! implementation the rest of the system uses.
//!
//! Run with: cargo test -p sovereign-crypto --test pq_kat -- --nocapture

use ml_dsa::{
    signature::{Keypair as _, Signer as _, Verifier as _},
    MlDsa87, Signature, SigningKey,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn emit_mldsa87_vectors() {
    // Fixed seed so the vector is reproducible.
    let seed = [7u8; 32];
    let sk = SigningKey::<MlDsa87>::from_seed(&seed.into());
    let vk = sk.verifying_key();
    let msg = b"sovereign capability grant v1";
    let sig: Signature<MlDsa87> = sk.sign(msg);

    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    println!("VK_LEN={}", vk_bytes.len());
    println!("SIG_LEN={}", sig_bytes.len());
    println!("MSG_HEX={}", hex(msg));
    println!("VK_HEX={}", hex(&vk_bytes));
    println!("SIG_HEX={}", hex(&sig_bytes));

    // A vector emitted from a broken signer would be useless, so check it here.
    assert!(vk.verify(msg, &sig).is_ok());
}
