//! The plug-in gate, as it exists *inside* a bare-metal kernel.
//!
//! A `no_std` library rather than a module of the kernel binary, for one practical reason: a
//! binary with its own `#[panic_handler]` cannot be `cargo test`ed on the host, so a gate written
//! as a module could only ever be exercised by booting a VM. As a library it gets ordinary unit
//! tests *and* the kernel's boot-time self-check, and both run the same source.
//!
//! This is the same decision the C module in `../kernel` makes, expressed in `no_std` Rust with
//! no allocator and no kernel API underneath it. It exists to answer one question honestly: is
//! the gate logic sound on its own, or does it only work because a host kernel supplies things?
//!
//! It is `no_std` and allocation-free, so the same code compiles for the host and for
//! `x86_64-unknown-none`. That is what makes it testable at all — a capability check you cannot
//! run is a capability check you do not know works.
//!
//! ## What is deliberately absent
//!
//! No signature verification. Verifying a hybrid ECDSA + ML-DSA grant in-kernel needs both
//! primitives, and pulling `p384`/`ml-dsa` into a bare-metal image is a separate project with
//! its own size and constant-time questions. This gate enforces the *policy* — device state,
//! rights, expiry, replay — which is the part that must be right before cryptography is worth
//! anything. The signatures are checked before a token ever reaches here; if that ordering ever
//! inverts, this gate would be trusting unauthenticated input, so it is stated plainly.

#![no_std]
/// Bytes in an encoded capability token. Must match `sovereign_ipc::CapabilityToken`.
pub const TOKEN_LEN: usize = 77;

/// Bit positions, matching `sovereign_ipc::Rights`.
pub mod rights {
    pub const SENSOR_READ: u32 = 1 << 0;
    pub const TELEMETRY_WRITE: u32 = 1 << 1;
    pub const NET_EGRESS: u32 = 1 << 2;
    pub const CRYPTO_OP: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;
    pub const KNOWN_MASK: u32 = 0b1_1111;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    Short,
    Version,
    ReservedRights,
    NotYetValid,
    Expired,
    Replay,
    Revoked,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Quarantined,
    Active,
    Revoked,
}

/// A parsed token. Fields are private so a caller cannot construct one that skipped parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    device_id: [u8; 16],
    rights: u32,
    issued_at: u64,
    expires_at: u64,
    counter_base: u64,
    nonce: [u8; 32],
}

impl Token {
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }
    pub fn rights(&self) -> u32 {
        self.rights
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn counter_base(&self) -> u64 {
        self.counter_base
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Parse the 77-byte wire form. Rejects reserved rights bits and unknown versions, because a
    /// future version with new bits must be refused rather than silently misinterpreted.
    pub fn parse(buf: &[u8]) -> Result<Self, GateError> {
        if buf.len() != TOKEN_LEN {
            return Err(GateError::Short);
        }
        if buf[0] != 1 {
            return Err(GateError::Version);
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&buf[1..17]);

        let rights = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
        if rights & !rights::KNOWN_MASK != 0 {
            return Err(GateError::ReservedRights);
        }

        let issued_at = u64::from_be_bytes(buf[21..29].try_into().map_err(|_| GateError::Short)?);
        let expires_at = u64::from_be_bytes(buf[29..37].try_into().map_err(|_| GateError::Short)?);
        let counter_base =
            u64::from_be_bytes(buf[37..45].try_into().map_err(|_| GateError::Short)?);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&buf[45..77]);

        Ok(Self {
            device_id,
            rights,
            issued_at,
            expires_at,
            counter_base,
            nonce,
        })
    }
}

/// Per-device gate state. Fixed size, no allocation: a kernel cannot grow a table on demand.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    state: State,
    /// Highest counter seen, for replay rejection.
    high_water: u64,
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            state: State::Quarantined,
            high_water: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Admit a token. Order matters and is deliberate:
    ///
    /// 1. state, because a revoked device must be refused whatever it presents;
    /// 2. validity window, because an expired token is the common case and should not touch the
    ///    replay counter;
    /// 3. replay, last, so a token is only marked used once everything else passed. Advancing the
    ///    counter before the checks would let an attacker burn a legitimate token by replaying it.
    ///
    /// On success the device becomes `Active` and the replay counter advances.
    pub fn admit(&mut self, t: &Token, now: u64) -> Result<u32, GateError> {
        match self.state {
            State::Revoked => return Err(GateError::Revoked),
            State::Quarantined => return Err(GateError::Quarantined),
            State::Active => {}
        }

        if now < t.issued_at {
            return Err(GateError::NotYetValid);
        }
        if now >= t.expires_at {
            return Err(GateError::Expired);
        }
        if t.counter_base <= self.high_water {
            return Err(GateError::Replay);
        }

        self.high_water = t.counter_base;
        Ok(t.rights)
    }

    /// Move a device from quarantine to active. Only meaningful after the plug-in handshake has
    /// authenticated the device out of band.
    pub fn activate(&mut self) {
        if self.state == State::Quarantined {
            self.state = State::Active;
        }
    }

    /// Revoke permanently. Not reversible: a revoked device re-enrols from scratch, which is the
    /// point of revocation.
    pub fn revoke(&mut self) {
        self.state = State::Revoked;
    }

    /// Does this device hold `want`?
    pub fn permits(&self, rights: u32, want: u32) -> bool {
        self.state == State::Active && rights & want == want
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a token wire image. Used by tests and by the boot self-check.
pub fn encode_token(
    device_id: [u8; 16],
    rights: u32,
    issued_at: u64,
    expires_at: u64,
    counter_base: u64,
    nonce: [u8; 32],
) -> [u8; TOKEN_LEN] {
    let mut b = [0u8; TOKEN_LEN];
    b[0] = 1;
    b[1..17].copy_from_slice(&device_id);
    b[17..21].copy_from_slice(&rights.to_be_bytes());
    b[21..29].copy_from_slice(&issued_at.to_be_bytes());
    b[29..37].copy_from_slice(&expires_at.to_be_bytes());
    b[37..45].copy_from_slice(&counter_base.to_be_bytes());
    b[45..77].copy_from_slice(&nonce);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(rights: u32, issued: u64, expires: u64, counter: u64) -> [u8; TOKEN_LEN] {
        encode_token([0xAB; 16], rights, issued, expires, counter, [0x11; 32])
    }

    fn active() -> Gate {
        let mut g = Gate::new();
        g.activate();
        g
    }

    #[test]
    fn parses_a_well_formed_token() {
        let t = Token::parse(&tok(rights::SENSOR_READ, 100, 200, 1)).expect("parse");
        assert_eq!(t.rights(), rights::SENSOR_READ);
        assert_eq!(t.expires_at(), 200);
        assert_eq!(t.counter_base(), 1);
    }

    #[test]
    fn wrong_length_is_refused() {
        assert_eq!(Token::parse(&[0u8; 10]).unwrap_err(), GateError::Short);
        assert_eq!(Token::parse(&[0u8; 78]).unwrap_err(), GateError::Short);
    }

    #[test]
    fn unknown_version_is_refused() {
        let mut b = tok(0, 0, 100, 1);
        b[0] = 2;
        assert_eq!(Token::parse(&b).unwrap_err(), GateError::Version);
    }

    #[test]
    fn reserved_rights_bits_are_refused() {
        // A future version might use bit 5. Today it must be refused, not ignored.
        let mut b = tok(0, 0, 100, 1);
        b[20] = 0b0010_0000;
        assert_eq!(Token::parse(&b).unwrap_err(), GateError::ReservedRights);
    }

    #[test]
    fn a_quarantined_device_is_refused_even_with_a_valid_token() {
        let mut g = Gate::new();
        let t = Token::parse(&tok(rights::SENSOR_READ, 0, 100, 1)).expect("parse");
        assert_eq!(g.admit(&t, 50).unwrap_err(), GateError::Quarantined);
    }

    #[test]
    fn a_revoked_device_is_refused_permanently() {
        let mut g = active();
        g.revoke();
        let t = Token::parse(&tok(rights::ADMIN, 0, 100, 1)).expect("parse");
        assert_eq!(g.admit(&t, 50).unwrap_err(), GateError::Revoked);
        g.activate(); // activation must not undo revocation
        assert_eq!(g.state(), State::Revoked);
        assert_eq!(g.admit(&t, 50).unwrap_err(), GateError::Revoked);
    }

    #[test]
    fn a_token_from_the_future_is_refused() {
        let mut g = active();
        let t = Token::parse(&tok(rights::SENSOR_READ, 100, 200, 1)).expect("parse");
        assert_eq!(g.admit(&t, 99).unwrap_err(), GateError::NotYetValid);
    }

    #[test]
    fn an_expired_token_is_refused_at_the_boundary() {
        let mut g = active();
        let t = Token::parse(&tok(rights::SENSOR_READ, 100, 200, 1)).expect("parse");
        // `now == expires_at` is expired: half-open intervals avoid the classic off-by-one that
        // makes a token valid for one extra instant.
        assert_eq!(g.admit(&t, 200).unwrap_err(), GateError::Expired);
        assert!(g.admit(&t, 199).is_ok());
    }

    #[test]
    fn a_replayed_token_is_refused() {
        let mut g = active();
        let t = Token::parse(&tok(rights::SENSOR_READ, 0, 100, 5)).expect("parse");
        assert_eq!(g.admit(&t, 10), Ok(rights::SENSOR_READ));
        assert_eq!(g.admit(&t, 10).unwrap_err(), GateError::Replay);
    }

    #[test]
    fn a_lower_counter_is_refused() {
        let mut g = active();
        let hi = Token::parse(&tok(rights::SENSOR_READ, 0, 100, 9)).expect("parse");
        let lo = Token::parse(&tok(rights::SENSOR_READ, 0, 100, 3)).expect("parse");
        assert!(g.admit(&hi, 10).is_ok());
        assert_eq!(g.admit(&lo, 10).unwrap_err(), GateError::Replay);
    }

    #[test]
    fn a_refused_token_does_not_advance_the_counter() {
        // Otherwise an attacker could burn a legitimate token by replaying it first.
        let mut g = active();
        let expired = Token::parse(&tok(rights::SENSOR_READ, 0, 100, 50)).expect("parse");
        assert_eq!(g.admit(&expired, 500).unwrap_err(), GateError::Expired);
        let good = Token::parse(&tok(rights::SENSOR_READ, 0, 1000, 1)).expect("parse");
        assert!(g.admit(&good, 10).is_ok(), "counter must still be at 0");
    }

    #[test]
    fn permits_requires_an_active_device_and_the_full_right_set() {
        let g = active();
        let both = rights::SENSOR_READ | rights::TELEMETRY_WRITE;
        assert!(g.permits(both, rights::SENSOR_READ));
        assert!(!g.permits(rights::SENSOR_READ, rights::TELEMETRY_WRITE));
        assert!(!g.permits(both, rights::ADMIN));
    }

    #[test]
    fn permits_is_false_when_quarantined() {
        let g = Gate::new();
        assert!(!g.permits(rights::ADMIN, rights::ADMIN));
    }

    #[test]
    fn encode_then_parse_roundtrips_every_field() {
        let b = encode_token([7; 16], 0b101, 1, 2, 3, [9; 32]);
        let t = Token::parse(&b).expect("parse");
        assert_eq!(t.device_id(), &[7u8; 16]);
        assert_eq!(t.rights(), 0b101);
        assert_eq!(t.nonce(), &[9u8; 32]);
    }
}
