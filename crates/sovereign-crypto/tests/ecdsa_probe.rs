// Emit a P-384 signature plus the pieces a kernel verifier needs.
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
use p384::SecretKey;
use sha2::{Digest, Sha384};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn emit_p384_probe() {
    let seed = [9u8; 48];
    let sk = SigningKey::from(SecretKey::from_slice(&seed).unwrap());
    let vk = sk.verifying_key();
    let msg = b"sovereign kernel ecdsa probe";

    let sig: Signature = sk.sign(msg);
    let sig_bytes = sig.to_bytes();

    // Raw X||Y, each 48 bytes big-endian.
    let point = vk.to_sec1_point(false);
    let xy = &point.as_bytes()[1..]; // skip the 0x04 prefix

    let digest = Sha384::digest(msg);

    println!("MSG={}", hex(msg));
    println!("XY={}", hex(xy));
    println!("SEC1={}", hex(point.as_bytes()));
    println!("DIGEST={}", hex(&digest));
    println!("SIG_RS={}", hex(&sig_bytes));
    println!("SIG_LEN={}", sig_bytes.len());
}
