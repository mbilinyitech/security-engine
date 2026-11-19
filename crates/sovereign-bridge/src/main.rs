//! `sovereign-bridge` — the operator-facing entry point.
//!
//! Two subcommands exist because they have very different trust requirements:
//!
//! * `ca` runs **offline**, ideally on an air-gapped machine. It mints the root key pair and
//!   signs device certificates. Nothing else in the system needs it.
//! * `enroll` runs **online** on the host. It performs a handshake with an attached device and
//!   prints the sealed capability grant.
//!
//! There is no "issue me a certificate" command. Certificates are produced only by `ca`, from
//! a root key that never touches the network, so a compromised host cannot mint credentials
//! for itself.

use std::process::ExitCode;

use sovereign_bridge::{
    attestation_payload, AttestationClaim, CapabilityGrant, DeviceCertificate, Handshake,
};
use sovereign_crypto::{labels, HybridSignature, HybridSigningKey, HybridVerifyingKey};
use sovereign_ipc::Rights;

const USAGE: &str = "\
sovereign-bridge — plug-in handshake and capability issuance

USAGE:
    sovereign-bridge ca init
        Generate a new key pair (root CA, or a device identity). Offline use only.

    sovereign-bridge ca certify <root-seed> <device-pubkey> <rights>
        Sign a device certificate. `rights` is a comma-separated list of:
        sensor,telemetry,net,crypto

    sovereign-bridge enroll <root-pubkey> <device-cert> <nonce> <device-seed>
        Device side of the handshake: answer a challenge, print the attestation claim.

    sovereign-bridge host <root-seed> <device-cert> <nonce> <claim> <session-key> <unix-now>
        Host side: verify an attestation claim, narrow the rights, mint the capability
        grant, and verify it the way the kernel driver would before printing it.

    sovereign-bridge verify <root-pubkey> <grant> <unix-now>
        Re-verify an existing grant exactly as the kernel driver would.

    sovereign-bridge kernel-grant <grant> <root-key-hex>
    sovereign-bridge kernel-grant-v2 <grant>
        Emit the 109-byte blob the kernel module accepts on write(): the 77-byte token
        followed by the 32-byte hmac-sha256 tag. Redirect it into /dev/sovereign_gate.

    Seeds are `<ecdsa-seed-hex>:<mldsa-seed-hex>`.

NOTES:
    * Keys are read from argv for brevity. In production load them from a TPM, HSM, or sealed
      file: argv is visible in `ps` to every user on the box.
    * ADMIN is never grantable through this tool. It requires a separate physical path.
";

/// Write one line to stdout.
///
/// A closed pipe (e.g. `sovereign-bridge ... | head`) is a normal end of output, not a
/// failure: Rust ignores SIGPIPE, so the write returns `BrokenPipe` instead. Treating that as
/// success keeps the process from panicking when a caller stops reading early.
fn emit_line(line: &str) -> Result<(), String> {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match writeln!(lock, "{line}") {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("failed writing to stdout: {e}")),
    }
}

/// `emit!(...)` formats and writes a line, propagating non-pipe errors.
macro_rules! emit {
    ($($arg:tt)*) => {
        emit_line(&format!($($arg)*))?
    };
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [] => {
            emit!("{USAGE}");
            Ok(())
        }
        [flag] if flag == "-h" || flag == "--help" || flag == "help" => {
            emit!("{USAGE}");
            Ok(())
        }
        [ca, init] if ca == "ca" && init == "init" => ca_init(),
        [ca, certify, root_seed, device_key, rights] if ca == "ca" && certify == "certify" => {
            ca_certify(root_seed, device_key, rights)
        }
        [cmd, root, cert, nonce, device_seed] if cmd == "enroll" => {
            enroll(root, cert, nonce, device_seed)
        }
        [cmd, root, cert, nonce, claim, session_key, now] if cmd == "host" => {
            host(root, cert, nonce, claim, session_key, now)
        }
        [cmd, root, grant, now] if cmd == "verify" => verify(root, grant, now),
        [cmd, grant, key] if cmd == "kernel-grant" => kernel_grant(grant, key),
        [cmd, grant] if cmd == "kernel-grant-v2" => kernel_grant_v2(grant),
        _ => Err(format!("unrecognised arguments\n\n{USAGE}")),
    }
}

fn ca_init() -> Result<(), String> {
    let sk = HybridSigningKey::generate().map_err(|e| e.to_string())?;
    let vk = sk.verifying_key();
    let (ecdsa_seed, mldsa_seed) = sk.seeds();

    emit!("root-ecdsa-seed={}", hex::encode(ecdsa_seed));
    emit!("root-mldsa-seed={}", hex::encode(mldsa_seed));
    emit!("root-public-key={}", hex::encode(vk.encode()));
    emit!("");
    emit!("Keep the seeds offline. Publish only root-public-key.");
    Ok(())
}

fn parse_rights(spec: &str) -> Result<Rights, String> {
    let mut rights = Rights::NONE;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        rights = rights.union(match part {
            "sensor" => Rights::SENSOR_READ,
            "telemetry" => Rights::TELEMETRY_WRITE,
            "net" => Rights::NET_EGRESS,
            "crypto" => Rights::CRYPTO_OP,
            "admin" => {
                return Err(
                    "ADMIN cannot be issued here; it requires the separate physical path"
                        .to_string(),
                )
            }
            other => return Err(format!("unknown right `{other}`")),
        });
    }
    Ok(rights)
}

fn ca_certify(root_seed_hex: &str, device_key_hex: &str, rights_spec: &str) -> Result<(), String> {
    let (ecdsa_seed, mldsa_seed) = parse_seed(root_seed_hex)?;
    let root = HybridSigningKey::from_seeds(ecdsa_seed, mldsa_seed);
    let device_key = HybridVerifyingKey::decode(&decode_hex(device_key_hex, "device key")?)
        .map_err(|e| e.to_string())?;
    let max_rights = parse_rights(rights_spec)?;

    // The device id is derived from its public key, so it cannot be chosen to collide with
    // another device's slot.
    let fingerprint = device_key.fingerprint();
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&fingerprint[..16]);

    let mut cert = DeviceCertificate {
        device_id,
        device_key,
        max_rights,
        root_signature: HybridSignature {
            ecdsa: [0u8; 96],
            mldsa: Vec::new(),
        },
    };
    cert.root_signature = root
        .sign(labels::CAPABILITY, &cert.signing_payload())
        .map_err(|e| e.to_string())?;

    emit!("device-id={}", hex::encode(device_id));
    emit!("device-max-rights=0x{:02x}", max_rights.bits());
    emit!("device-cert={}", hex::encode(encode_cert(&cert)));
    Ok(())
}

fn enroll(
    root_hex: &str,
    cert_hex: &str,
    nonce_hex: &str,
    device_seed_hex: &str,
) -> Result<(), String> {
    let root = HybridVerifyingKey::decode(&decode_hex(root_hex, "root key")?)
        .map_err(|e| e.to_string())?;
    let cert = decode_cert(&decode_hex(cert_hex, "device cert")?)?;
    let nonce = parse_nonce(nonce_hex)?;

    let (ecdsa_seed, mldsa_seed) = parse_seed(device_seed_hex)?;
    let device = HybridSigningKey::from_seeds(ecdsa_seed, mldsa_seed);
    let device_key = device.verifying_key();

    // Refuse before signing if the certificate is not for this key: never produce an
    // attestation for a device we do not control.
    if cert.device_key != device_key {
        return Err("certificate is not for this device key".to_string());
    }

    // Check the certificate is genuine before we spend a signature on it.
    root.verify(
        labels::CAPABILITY,
        &cert.signing_payload(),
        &cert.root_signature,
    )
    .map_err(|_| "device certificate is not signed by this root".to_string())?;

    let payload = attestation_payload(&nonce, &cert.device_id, cert.max_rights);
    let signature = device
        .sign(labels::ATTESTATION, &payload)
        .map_err(|e| e.to_string())?;

    let claim = AttestationClaim {
        device_id: cert.device_id,
        requested_rights: cert.max_rights,
        device_key,
        signature,
    };

    emit!("nonce={nonce_hex}");
    emit!("attestation={}", hex::encode(encode_claim(&claim)));
    emit!(
        "requested-rights=0x{:02x} (the host narrows this; ADMIN is never grantable)",
        cert.max_rights.bits()
    );
    Ok(())
}

/// Host side: verify a claim, narrow the rights, mint and self-check the grant.
///
/// The nonce is the entire handshake state, so this command is stateless and reproducible.
/// Whoever holds the nonce can only produce one valid claim for it, which is why the nonce
/// must be fresh and secret until the device answers.
fn host(
    root_seed_hex: &str,
    cert_hex: &str,
    nonce_hex: &str,
    claim_hex: &str,
    session_key_hex: &str,
    now: &str,
) -> Result<(), String> {
    let (ecdsa_seed, mldsa_seed) = parse_seed(root_seed_hex)?;
    let root_signing = HybridSigningKey::from_seeds(ecdsa_seed, mldsa_seed);
    let root_verifying = root_signing.verifying_key();

    let cert = decode_cert(&decode_hex(cert_hex, "device cert")?)?;
    let claim = decode_claim(&decode_hex(claim_hex, "attestation")?)?;
    let nonce = parse_nonce(nonce_hex)?;
    let session_key: [u8; 32] = decode_hex(session_key_hex, "session key")?
        .as_slice()
        .try_into()
        .map_err(|_| "session key must be 32 bytes".to_string())?;
    let now: u64 = now
        .parse()
        .map_err(|_| "unix-now must be a number".to_string())?;

    // Reconstruct the handshake at the instant it was created. The nonce is the whole state.
    let mut hs = Handshake::from_challenge(nonce, now).map_err(|e| e.to_string())?;
    let granted = hs
        .accept_attestation(now, &cert, &claim, &root_verifying)
        .map_err(|e| e.to_string())?;

    let token = hs.issue_capability(now, 1).map_err(|e| e.to_string())?;
    let root_signature = root_signing
        .sign(labels::CAPABILITY, &token.encode())
        .map_err(|e| e.to_string())?;
    let grant = CapabilityGrant {
        token,
        root_signature,
    };

    // Self-check exactly as the kernel will, so we never emit a grant we would reject.
    grant
        .verify(&root_verifying, now)
        .map_err(|e| format!("minted grant failed self-verification: {e}"))?;

    // Prove the sealed-frame path works before handing the grant out.
    let mut session =
        sovereign_bridge::Session::from_grant(&grant, &root_verifying, now, session_key)
            .map_err(|e| e.to_string())?;
    let probe = session
        .seal(now, granted, b"probe")
        .map_err(|e| e.to_string())?;
    session
        .open(&probe, now)
        .map_err(|e| format!("sealed-frame self-test failed: {e}"))?;

    emit!("valid=true");
    emit!("device-id={}", hex::encode(grant.token.device_id));
    emit!("granted-rights=0x{:02x}", grant.token.rights.bits());
    emit!("expires-at={}", grant.token.expires_at);
    emit!("grant={}", hex::encode(grant.encode()));
    Ok(())
}

/// Emit the exact blob the kernel module expects: token wire bytes then the HMAC tag.
///
/// This is the seam between the hybrid-signature world (ECDSA + ML-DSA-87) and the kernel,
/// which can only compute hmac(sha256) today. The grant is still verified as a hybrid
/// signature first: the tag is derived from a grant that already passed that check, not a
/// substitute for it.
fn kernel_grant(grant_hex: &str, key_hex: &str) -> Result<(), String> {
    let grant =
        CapabilityGrant::decode(&decode_hex(grant_hex, "grant")?).map_err(|e| e.to_string())?;

    let key_bytes = decode_hex(key_hex, "root key")?;
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "root key must be exactly 32 bytes".to_string())?;

    let token_wire = grant.token.encode();
    if token_wire.len() != 77 {
        return Err(format!(
            "token encoded to {} bytes, kernel expects 77",
            token_wire.len()
        ));
    }

    let blob = sovereign_crypto::grant_wire(&key, &token_wire);
    emit!("{}", hex::encode(&blob));
    emit!("# {} bytes: 77 token + 32 hmac-sha256 tag", blob.len());
    emit!(
        "# write with: printf '{}' | xxd -r -p > /dev/sovereign_gate",
        hex::encode(&blob)
    );
    Ok(())
}

/// Emit the v2 blob: the grant's own hybrid signature over the token, for a kernel that
/// verifies ECDSA P-384 and ML-DSA-87 itself.
///
/// Unlike `kernel-grant`, nothing here is derived from a symmetric key. The signature is the
/// one the root CA already produced, so the module needs only the matching public keys. A
/// kernel compromise therefore cannot mint a grant.
fn kernel_grant_v2(grant_hex: &str) -> Result<(), String> {
    let grant =
        CapabilityGrant::decode(&decode_hex(grant_hex, "grant")?).map_err(|e| e.to_string())?;

    let token_wire = grant.token.encode();
    if token_wire.len() != 77 {
        return Err(format!(
            "token encoded to {} bytes, kernel expects 77",
            token_wire.len()
        ));
    }

    // Reuse the grant's existing signature rather than signing again: it is already over
    // exactly these token bytes under the capability domain, which is what the kernel checks.
    let blob = sovereign_crypto::grant_v2_encode_parts(&token_wire, &grant.root_signature);

    // Self-check the way the kernel will, so a blob that would be rejected is never emitted.
    let parsed = sovereign_crypto::grant_v2_decode(&blob).map_err(|e| e.to_string())?;
    if parsed.token != &token_wire[..] {
        return Err("round-trip changed the token bytes".to_string());
    }

    emit!("{}", hex::encode(&blob));
    emit!(
        "# {} bytes: 5 header + 77 token + 2 + {} ecdsa + 2 + {} mldsa",
        blob.len(),
        sovereign_crypto::sizes::P384_SIG,
        sovereign_crypto::sizes::ML_DSA_87_SIG
    );
    emit!(
        "# write with: printf '{}' | xxd -r -p > /dev/sovereign_gate",
        hex::encode(&blob)
    );
    Ok(())
}

fn verify(root_hex: &str, grant_hex: &str, now: &str) -> Result<(), String> {
    let root = HybridVerifyingKey::decode(&decode_hex(root_hex, "root key")?)
        .map_err(|e| e.to_string())?;
    let grant =
        CapabilityGrant::decode(&decode_hex(grant_hex, "grant")?).map_err(|e| e.to_string())?;
    let now: u64 = now
        .parse()
        .map_err(|_| "unix-now must be a number".to_string())?;

    grant.verify(&root, now).map_err(|e| e.to_string())?;
    emit!("valid=true");
    emit!("device-id={}", hex::encode(grant.token.device_id));
    emit!("rights=0x{:02x}", grant.token.rights.bits());
    emit!("expires-at={}", grant.token.expires_at);
    Ok(())
}

fn parse_nonce(s: &str) -> Result<[u8; 32], String> {
    decode_hex(s, "nonce")?
        .as_slice()
        .try_into()
        .map_err(|_| "nonce must be 32 bytes".to_string())
}

fn decode_claim(buf: &[u8]) -> Result<AttestationClaim, String> {
    // device_id(16) | rights(4) | verifying key | signature
    const PREFIX: usize = 16 + 4;
    if buf.len() < PREFIX {
        return Err("attestation too short".to_string());
    }
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&buf[..16]);
    let bits = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let requested_rights = Rights::from_bits(bits)
        .ok_or_else(|| "attestation has reserved rights bits".to_string())?;

    let vk_len = 97 + 2592;
    if buf.len() < PREFIX + vk_len {
        return Err("attestation truncated before key".to_string());
    }
    let device_key =
        HybridVerifyingKey::decode(&buf[PREFIX..PREFIX + vk_len]).map_err(|e| e.to_string())?;
    let signature = HybridSignature::decode(&buf[PREFIX + vk_len..]).map_err(|e| e.to_string())?;

    Ok(AttestationClaim {
        device_id,
        requested_rights,
        device_key,
        signature,
    })
}

fn decode_hex(s: &str, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|_| format!("{what} is not valid hex"))
}

fn parse_seed(s: &str) -> Result<([u8; 48], [u8; 32]), String> {
    // Accept "ecdsa:mldsa" so both halves travel as one argument.
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| "root seed must be `<ecdsa-seed-hex>:<mldsa-seed-hex>`".to_string())?;
    let ecdsa: [u8; 48] = decode_hex(a, "ecdsa seed")?
        .as_slice()
        .try_into()
        .map_err(|_| "ecdsa seed must be 48 bytes".to_string())?;
    let mldsa: [u8; 32] = decode_hex(b, "mldsa seed")?
        .as_slice()
        .try_into()
        .map_err(|_| "mldsa seed must be 32 bytes".to_string())?;
    Ok((ecdsa, mldsa))
}

fn encode_cert(cert: &DeviceCertificate) -> Vec<u8> {
    let payload = cert.signing_payload();
    let sig = cert.root_signature.encode();
    let mut out = Vec::with_capacity(2 + payload.len() + sig.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&sig);
    out
}

fn decode_cert(buf: &[u8]) -> Result<DeviceCertificate, String> {
    if buf.len() < 2 {
        return Err("certificate too short".to_string());
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err("certificate truncated".to_string());
    }
    let payload = &buf[2..2 + len];
    if payload.len() != 16 + 4 + 97 + 2592 {
        return Err("certificate payload has the wrong length".to_string());
    }

    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&payload[..16]);
    let rights_bits = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let max_rights = Rights::from_bits(rights_bits)
        .ok_or_else(|| "certificate has reserved rights bits".to_string())?;
    let device_key = HybridVerifyingKey::decode(&payload[20..]).map_err(|e| e.to_string())?;
    let root_signature = HybridSignature::decode(&buf[2 + len..]).map_err(|e| e.to_string())?;

    Ok(DeviceCertificate {
        device_id,
        device_key,
        max_rights,
        root_signature,
    })
}

fn encode_claim(claim: &AttestationClaim) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&claim.device_id);
    out.extend_from_slice(&claim.requested_rights.bits().to_be_bytes());
    out.extend_from_slice(&claim.device_key.encode());
    out.extend_from_slice(&claim.signature.encode());
    out
}
