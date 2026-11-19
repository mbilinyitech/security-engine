//! The kernel's C parser hard-codes the token layout, so the two must not drift apart.
//!
//! `kernel/sov_core.h` defines `SOV_TOKEN_LEN`, the field offsets, and reads big-endian integers
//! at those offsets. If `CapabilityToken::encode` ever changes, the kernel would silently parse
//! garbage — and "silently" is the dangerous part: a shifted field could turn a read-only right
//! into an admin one. These tests fail loudly instead.

use sovereign_ipc::{CapabilityToken, Rights};

/// Mirrors `SOV_TOKEN_LEN` in kernel/sov_core.h.
const C_TOKEN_LEN: usize = 77;
/// Mirrors the SOV_OFF_* constants in kernel/sov_core.h.
const C_OFF_VERSION: usize = 0;
const C_OFF_DEVICE_ID: usize = 1;
const C_OFF_RIGHTS: usize = 17;
const C_OFF_ISSUED_AT: usize = 21;
const C_OFF_EXPIRES_AT: usize = 29;
const C_OFF_COUNTER_BASE: usize = 37;
const C_OFF_NONCE: usize = 45;

fn token() -> CapabilityToken {
    CapabilityToken {
        device_id: [0xAB; 16],
        rights: Rights::SENSOR_READ,
        issued_at: 0x1122_3344_5566_7788,
        expires_at: 0x0102_0304_0506_0708,
        counter_base: 0xDEAD_BEEF_CAFE_0001,
        handshake_nonce: [0xCD; 32],
    }
}

#[test]
fn the_encoded_token_is_exactly_the_length_the_kernel_expects() {
    assert_eq!(CapabilityToken::ENCODED_LEN, C_TOKEN_LEN);
    assert_eq!(token().encode().len(), C_TOKEN_LEN);
}

#[test]
fn every_field_sits_at_the_offset_the_kernel_reads() {
    let enc = token().encode();

    assert_eq!(enc[C_OFF_VERSION], 1, "version byte");
    assert_eq!(&enc[C_OFF_DEVICE_ID..C_OFF_DEVICE_ID + 16], &[0xAB; 16]);

    // The kernel reads these as big-endian. Reading them back the same way is the check.
    let rights = u32::from_be_bytes(enc[C_OFF_RIGHTS..C_OFF_RIGHTS + 4].try_into().unwrap());
    assert_eq!(rights, Rights::SENSOR_READ.bits(), "rights");

    let issued = u64::from_be_bytes(
        enc[C_OFF_ISSUED_AT..C_OFF_ISSUED_AT + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(issued, 0x1122_3344_5566_7788, "issued_at");

    let expires = u64::from_be_bytes(
        enc[C_OFF_EXPIRES_AT..C_OFF_EXPIRES_AT + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(expires, 0x0102_0304_0506_0708, "expires_at");

    let base = u64::from_be_bytes(
        enc[C_OFF_COUNTER_BASE..C_OFF_COUNTER_BASE + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(base, 0xDEAD_BEEF_CAFE_0001, "counter_base");

    assert_eq!(&enc[C_OFF_NONCE..C_OFF_NONCE + 32], &[0xCD; 32], "nonce");
}

#[test]
fn the_nonce_is_the_last_field() {
    // If a field were added after the nonce, the kernel's fixed 77-byte read would truncate it
    // and the tag would cover different bytes than the kernel hashes.
    assert_eq!(C_OFF_NONCE + 32, C_TOKEN_LEN);
}

#[test]
fn the_kernel_wire_length_is_token_plus_tag() {
    // sov_write() requires exactly this many bytes: 77-byte token + 32-byte tag.
    const C_WIRE_LEN: usize = 77 + 32;
    assert_eq!(CapabilityToken::ENCODED_LEN + 32, C_WIRE_LEN);
}

#[test]
fn admin_does_not_share_a_bit_with_a_read_only_grant() {
    // The kernel refuses rights == 0 but does not know which bits are dangerous; that has to be
    // enforced before the token is minted. This pins the bit that must never appear.
    let admin = Rights::ADMIN.bits();
    assert_ne!(admin, 0);
    assert_eq!(Rights::SENSOR_READ.bits() & admin, 0);
}
