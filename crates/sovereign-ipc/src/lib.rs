//! Wire protocol shared by the Sovereign user-space bridge and the Rust kernel driver.
//!
//! Everything here is a fixed-layout, explicitly versioned encoding. We deliberately do not
//! use a generic serializer: a self-describing deserializer sitting on the kernel boundary is
//! an attack surface (length smuggling, recursive types, allocation amplification). Every
//! reader in this crate is bounds-checked and returns `Err` instead of panicking, because a
//! panic in a driver-adjacent process is a denial of service at best.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]
// Tests assert on failures, so they are allowed to unwrap and panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)
)]

use core::fmt;
use zeroize::Zeroize;

/// Bumped whenever the layout below changes incompatibly.
pub const PROTOCOL_VERSION: u8 = 1;

/// Frame magic. Frames that do not start with this are dropped before any parsing.
pub const FRAME_MAGIC: [u8; 4] = *b"SOVR";

/// Header is `magic(4) | version(1) | opcode(1) | flags(2) | len(4)`.
pub const HEADER_LEN: usize = 12;

/// Hard ceiling on a single frame payload. Enforced *before* any allocation, so a hostile
/// peer cannot ask us for gigabytes by claiming a large length field.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// Largest a capability token can encode to, used to bound token buffers.
pub const MAX_CAPABILITY_TOKEN: usize = 77;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Not enough bytes to complete the requested read.
    Truncated,
    /// Frame does not begin with [`FRAME_MAGIC`].
    BadMagic,
    /// Peer speaks a protocol version we do not implement.
    UnsupportedVersion(u8),
    /// Opcode is not one we recognise.
    UnknownOpcode(u8),
    /// Declared payload length exceeds [`MAX_PAYLOAD`] or the caller's limit.
    FrameTooLarge { declared: usize, limit: usize },
    /// A field held a value outside its permitted set (e.g. reserved bits set).
    InvalidField(&'static str),
    /// Underlying transport failed.
    Io,
    /// Frame carried trailing bytes the layout does not account for.
    TrailingBytes,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated frame"),
            Self::BadMagic => write!(f, "bad frame magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::UnknownOpcode(o) => write!(f, "unknown opcode {o}"),
            Self::FrameTooLarge { declared, limit } => {
                write!(f, "frame too large: declared {declared}, limit {limit}")
            }
            Self::InvalidField(what) => write!(f, "invalid field: {what}"),
            Self::Io => write!(f, "transport error"),
            Self::TrailingBytes => write!(f, "trailing bytes after frame payload"),
        }
    }
}

impl std::error::Error for IpcError {}

/// Operations the bridge may ask the kernel driver to perform, and replies it sends back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// Bridge -> kernel: identify ourselves, advertise protocol version.
    Hello = 1,
    /// Kernel -> bridge: fresh challenge nonce for device attestation.
    AttestChallenge = 2,
    /// Bridge -> kernel: signed attestation response bound to that challenge.
    AttestResponse = 3,
    /// Kernel -> bridge: capability granted, with the signed token.
    CapabilityGrant = 4,
    /// Bridge -> kernel: encrypted payload for the device.
    Data = 5,
    /// Kernel -> bridge: zeroize all DMA buffers and tear the session down.
    Wipe = 6,
    /// Either direction: the peer refused the operation. Carries a machine-readable code.
    Refuse = 7,
}

impl OpCode {
    pub fn from_u8(v: u8) -> Result<Self, IpcError> {
        Ok(match v {
            1 => Self::Hello,
            2 => Self::AttestChallenge,
            3 => Self::AttestResponse,
            4 => Self::CapabilityGrant,
            5 => Self::Data,
            6 => Self::Wipe,
            7 => Self::Refuse,
            other => return Err(IpcError::UnknownOpcode(other)),
        })
    }
}

/// A single protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: OpCode,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: OpCode, payload: Vec<u8>) -> Result<Self, IpcError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(IpcError::FrameTooLarge {
                declared: payload.len(),
                limit: MAX_PAYLOAD,
            });
        }
        Ok(Self {
            opcode,
            flags: 0,
            payload,
        })
    }

    /// Serialise with the length prefix. The length is taken from `payload.len()`, never from
    /// a caller-supplied value.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&FRAME_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.push(self.opcode as u8);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse from a complete buffer. Rejects trailing bytes so that concatenated frames cannot
    /// be used to smuggle a second, unvalidated message past the first.
    pub fn decode(buf: &[u8]) -> Result<Self, IpcError> {
        Self::decode_with_limit(buf, MAX_PAYLOAD)
    }

    pub fn decode_with_limit(buf: &[u8], limit: usize) -> Result<Self, IpcError> {
        if buf.len() < HEADER_LEN {
            return Err(IpcError::Truncated);
        }
        if buf[0..4] != FRAME_MAGIC {
            return Err(IpcError::BadMagic);
        }
        let version = buf[4];
        if version != PROTOCOL_VERSION {
            return Err(IpcError::UnsupportedVersion(version));
        }
        let opcode = OpCode::from_u8(buf[5])?;
        let flags = u16::from_be_bytes([buf[6], buf[7]]);
        let declared = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;

        let effective_limit = limit.min(MAX_PAYLOAD);
        if declared > effective_limit {
            return Err(IpcError::FrameTooLarge {
                declared,
                limit: effective_limit,
            });
        }
        let end = HEADER_LEN
            .checked_add(declared)
            .ok_or(IpcError::FrameTooLarge {
                declared,
                limit: effective_limit,
            })?;
        if buf.len() < end {
            return Err(IpcError::Truncated);
        }
        if buf.len() > end {
            return Err(IpcError::TrailingBytes);
        }
        Ok(Self {
            opcode,
            flags,
            payload: buf[HEADER_LEN..end].to_vec(),
        })
    }
}

/// Read one frame from a stream, allocating only after the declared length has been validated.
pub fn read_frame<R: std::io::Read>(reader: &mut R) -> Result<Frame, IpcError> {
    read_frame_with_limit(reader, MAX_PAYLOAD)
}

pub fn read_frame_with_limit<R: std::io::Read>(
    reader: &mut R,
    limit: usize,
) -> Result<Frame, IpcError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|_| IpcError::Io)?;

    if header[0..4] != FRAME_MAGIC {
        return Err(IpcError::BadMagic);
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(header[4]));
    }
    let opcode = OpCode::from_u8(header[5])?;
    let flags = u16::from_be_bytes([header[6], header[7]]);
    let declared = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

    let effective_limit = limit.min(MAX_PAYLOAD);
    if declared > effective_limit {
        // Refuse before allocating. The caller is expected to drop the connection.
        return Err(IpcError::FrameTooLarge {
            declared,
            limit: effective_limit,
        });
    }

    let mut payload = vec![0u8; declared];
    reader.read_exact(&mut payload).map_err(|_| IpcError::Io)?;
    Ok(Frame {
        opcode,
        flags,
        payload,
    })
}

pub fn write_frame<W: std::io::Write>(writer: &mut W, frame: &Frame) -> Result<(), IpcError> {
    let encoded = frame.encode();
    writer.write_all(&encoded).map_err(|_| IpcError::Io)?;
    writer.flush().map_err(|_| IpcError::Io)
}

/// Least-privilege capability rights. Bits outside [`Rights::KNOWN_MASK`] are rejected at
/// parse time so a future-version bit cannot be smuggled past an older verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Zeroize)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    /// May read the device's own sensor surface.
    pub const SENSOR_READ: Rights = Rights(1 << 0);
    /// May emit telemetry records for this device.
    pub const TELEMETRY_WRITE: Rights = Rights(1 << 1);
    /// May egress through the stealth tunnel.
    pub const NET_EGRESS: Rights = Rights(1 << 2);
    /// May request crypto operations (sealing/unsealing frames).
    pub const CRYPTO_OP: Rights = Rights(1 << 3);
    /// May administer the device: reflash, revoke, wipe. Never granted to a plug-in.
    pub const ADMIN: Rights = Rights(1 << 4);

    pub const KNOWN_MASK: u32 = 0b1_1111;

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from raw bits, rejecting reserved bits.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::KNOWN_MASK != 0 {
            None
        } else {
            Some(Rights(bits))
        }
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The subset both sides agree on. Used to enforce "never wider than the certificate".
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }
}

/// A capability granted to one device for one session.
///
/// The token is authenticated by the root CA's hybrid signature (see `sovereign-crypto`), so the
/// kernel can verify it without trusting the bridge process that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct CapabilityToken {
    pub device_id: [u8; 16],
    pub rights: Rights,
    /// Unix seconds at issuance.
    pub issued_at: u64,
    /// Unix seconds after which the kernel must refuse this token.
    pub expires_at: u64,
    /// First counter value the device may use. Frames below this are replays.
    pub counter_base: u64,
    /// The attestation challenge this token is bound to. Prevents token transplant between
    /// sessions: a token captured from session A is useless in session B.
    pub handshake_nonce: [u8; 32],
}

impl CapabilityToken {
    pub const ENCODED_LEN: usize = 1 + 16 + 4 + 8 + 8 + 8 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::ENCODED_LEN);
        w.u8(PROTOCOL_VERSION);
        w.bytes(&self.device_id);
        w.u32(self.rights.bits());
        w.u64(self.issued_at);
        w.u64(self.expires_at);
        w.u64(self.counter_base);
        w.bytes(&self.handshake_nonce);
        w.finish()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, IpcError> {
        let mut r = Reader::new(buf);
        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(IpcError::UnsupportedVersion(version));
        }
        let device_id = r.array::<16>()?;
        let rights = Rights::from_bits(r.u32()?).ok_or(IpcError::InvalidField("rights"))?;
        let issued_at = r.u64()?;
        let expires_at = r.u64()?;
        let counter_base = r.u64()?;
        let handshake_nonce = r.array::<32>()?;
        r.finish()?;
        Ok(Self {
            device_id,
            rights,
            issued_at,
            expires_at,
            counter_base,
            handshake_nonce,
        })
    }

    /// Expiry is checked by the kernel against its own clock, not by the bridge.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }
}

/// A sealed payload produced by the bridge, ready to be handed to the stealth tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFrame {
    pub capability_id: [u8; 16],
    /// Monotonic per-capability counter. The receiver keeps a replay window over this.
    pub counter: u64,
    /// Key epoch, so a rotation can be observed without ambiguity.
    pub epoch: u32,
    /// XChaCha20-Poly1305 nonce. 24 bytes so random nonces are safe at any volume.
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl SealedFrame {
    /// Size of the associated-data header.
    pub const HEADER_LEN: usize = 16 + 8 + 4;

    /// Capability id (16) | counter (8) | epoch (4), used verbatim as AEAD associated data.
    ///
    /// The nonce is deliberately *not* included: it is the AEAD's own input, so a wrong nonce
    /// already fails authentication, and folding it in here would make the header depend on a
    /// value that is only known after encryption.
    ///
    /// Binding the capability id stops a frame being replayed into a different device's
    /// session; binding the counter stops reordering and replay; binding the epoch stops a
    /// frame from surviving a key rotation.
    pub fn associated_data(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::HEADER_LEN);
        w.bytes(&self.capability_id);
        w.u64(self.counter);
        w.u32(self.epoch);
        w.finish()
    }

    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        if self.ciphertext.len() > MAX_PAYLOAD {
            return Err(IpcError::FrameTooLarge {
                declared: self.ciphertext.len(),
                limit: MAX_PAYLOAD,
            });
        }
        let mut w = Writer::with_capacity(1 + 16 + 8 + 4 + 24 + 4 + self.ciphertext.len());
        w.u8(PROTOCOL_VERSION);
        w.bytes(&self.capability_id);
        w.u64(self.counter);
        w.u32(self.epoch);
        w.bytes(&self.nonce);
        w.u32(self.ciphertext.len() as u32);
        w.bytes(&self.ciphertext);
        Ok(w.finish())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, IpcError> {
        let mut r = Reader::new(buf);
        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(IpcError::UnsupportedVersion(version));
        }
        let capability_id = r.array::<16>()?;
        let counter = r.u64()?;
        let epoch = r.u32()?;
        let nonce = r.array::<24>()?;
        let ct_len = r.u32()? as usize;
        if ct_len > MAX_PAYLOAD {
            return Err(IpcError::FrameTooLarge {
                declared: ct_len,
                limit: MAX_PAYLOAD,
            });
        }
        let ciphertext = r.bytes(ct_len)?.to_vec();
        r.finish()?;
        Ok(Self {
            capability_id,
            counter,
            epoch,
            nonce,
            ciphertext,
        })
    }
}

/// Append-only writer with a fixed, pre-validated layout.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Bounds-checked reader. Every accessor returns `Err` rather than panicking.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], IpcError> {
        let end = self.pos.checked_add(n).ok_or(IpcError::Truncated)?;
        if end > self.buf.len() {
            return Err(IpcError::Truncated);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, IpcError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, IpcError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, IpcError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, IpcError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], IpcError> {
        self.take(n)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], IpcError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Fails if the caller did not consume the whole buffer, which catches layout drift and
    /// hidden fields between implementations.
    pub fn finish(&self) -> Result<(), IpcError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(IpcError::TrailingBytes)
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = Frame::new(OpCode::Data, vec![1, 2, 3]).expect("frame");
        let enc = f.encode();
        assert_eq!(Frame::decode(&enc).expect("decode"), f);
    }

    #[test]
    fn rejects_oversized_declared_length_without_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FRAME_MAGIC);
        buf.push(PROTOCOL_VERSION);
        buf.push(OpCode::Data as u8);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&u32::MAX.to_be_bytes());

        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut enc = Frame::new(OpCode::Hello, vec![0xAA])
            .expect("frame")
            .encode();
        enc.push(0x00);
        assert_eq!(Frame::decode(&enc).unwrap_err(), IpcError::TrailingBytes);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut enc = Frame::new(OpCode::Hello, vec![]).expect("frame").encode();
        enc[0] = b'X';
        assert_eq!(Frame::decode(&enc).unwrap_err(), IpcError::BadMagic);
    }

    #[test]
    fn rejects_unknown_opcode() {
        let mut enc = Frame::new(OpCode::Hello, vec![]).expect("frame").encode();
        enc[5] = 0xEE;
        assert!(matches!(
            Frame::decode(&enc).unwrap_err(),
            IpcError::UnknownOpcode(0xEE)
        ));
    }

    #[test]
    fn reserved_rights_bits_are_rejected() {
        assert!(Rights::from_bits(1 << 5).is_none());
        assert_eq!(
            Rights::from_bits(0b1_1111).expect("known bits").bits(),
            Rights::KNOWN_MASK
        );
    }

    #[test]
    fn rights_intersection_never_widens() {
        let granted = Rights::SENSOR_READ.union(Rights::NET_EGRESS);
        let ceiling = Rights::SENSOR_READ;
        assert_eq!(granted.intersect(ceiling), Rights::SENSOR_READ);
        assert!(!granted.intersect(ceiling).contains(Rights::NET_EGRESS));
    }

    #[test]
    fn capability_token_roundtrip_and_tamper_detection() {
        let tok = CapabilityToken {
            device_id: [7u8; 16],
            rights: Rights::SENSOR_READ,
            issued_at: 100,
            expires_at: 200,
            counter_base: 1,
            handshake_nonce: [9u8; 32],
        };
        let enc = tok.encode();
        assert_eq!(enc.len(), CapabilityToken::ENCODED_LEN);
        assert_eq!(CapabilityToken::decode(&enc).expect("decode"), tok);

        // Flip the expiry to something far future; the encoding itself must not accept a
        // shortened buffer, and callers must verify the signature (see bridge tests).
        assert_eq!(
            CapabilityToken::decode(&enc[..enc.len() - 1]).unwrap_err(),
            IpcError::Truncated
        );
    }

    #[test]
    fn token_expiry_boundary() {
        let tok = CapabilityToken {
            device_id: [0u8; 16],
            rights: Rights::NONE,
            issued_at: 10,
            expires_at: 20,
            counter_base: 0,
            handshake_nonce: [0u8; 32],
        };
        assert!(!tok.is_valid_at(9));
        assert!(tok.is_valid_at(10));
        assert!(tok.is_valid_at(19));
        assert!(!tok.is_valid_at(20));
    }

    #[test]
    fn sealed_frame_roundtrip() {
        let f = SealedFrame {
            capability_id: [3u8; 16],
            counter: 42,
            epoch: 1,
            nonce: [5u8; 24],
            ciphertext: vec![0xDE, 0xAD],
        };
        let enc = f.encode().expect("encode");
        assert_eq!(SealedFrame::decode(&enc).expect("decode"), f);
        assert_eq!(f.associated_data().len(), SealedFrame::HEADER_LEN);
    }

    #[test]
    fn reader_never_panics_on_short_input() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u64().unwrap_err(), IpcError::Truncated);
        assert_eq!(r.remaining(), 2);
    }
}
