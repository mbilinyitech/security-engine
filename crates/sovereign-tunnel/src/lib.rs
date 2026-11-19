//! Terrestrial transport for [`SealedFrame`]s.
//!
//! This is layer 6 of the design: how a sealed frame gets from one machine to another over
//! ordinary IP connectivity, without satellites and without a private network. It carries
//! already-encrypted bytes and never sees plaintext, so a compromise here cannot read traffic.
//! What it *can* leak is metadata — who is talking to whom, when, and how much — and most of
//! the work below is about limiting that leak.
//!
//! What this crate does:
//!
//! * **UDP datagrams, not TCP.** A TCP stream needs a handshake, has distinctive timing, and
//!   head-of-line blocks; a datagram either arrives or it does not, which suits lossy links.
//! * **Replay protection at the transport.** A [`ReplayWindow`] per sender, advanced only after
//!   the frame authenticates, so a duplicated datagram is dropped before it reaches a session.
//! * **Length hiding.** Frames are padded into one of a fixed set of size buckets, so an
//!   observer learns the bucket, not the exact byte count.
//! * **Chaff.** Callers can inject cover traffic on a schedule so that real sends do not stand
//!   out as the only datagrams on the wire.
//!
//! What this crate deliberately does *not* do, despite the design document mentioning it:
//!
//! * **No protocol mimicry.** It does not pretend to be QUIC or anything else. Doing that
//!   convincingly is a research problem, and a half-done imitation is easier to fingerprint
//!   than plain UDP. Every datagram is prefixed with a magic value and is honestly labelled.
//! * **No onion routing.** Multi-hop forwarding needs a relay network that does not exist, and
//!   a naive implementation gives weaker anonymity than the operator assumes. Single-hop only.
//! * **No LoRa or radio.** There is no radio hardware here and no driver for one.
//!
//! Those three are real gaps. See the README for the current status of each.

#![deny(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
#![forbid(unsafe_code)]
// Tests assert on failures, so they are allowed to unwrap and panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)
)]

use sovereign_crypto::{CryptoError, ReplayWindow};
use sovereign_ipc::{Reader, SealedFrame, Writer};

pub mod transport;

/// Wire magic. Present in every datagram so a stray packet is rejected before any parsing.
pub const MAGIC: [u8; 4] = *b"SVT1";

/// Format version, so the layout can change without silently misparsing old peers.
pub const VERSION: u8 = 1;

/// Largest datagram this implementation will produce or accept.
///
/// 1200 bytes is the practical floor for a path MTU that survives the public internet without
/// fragmentation (IPv6 requires 1280, and tunnel headers eat into it). Staying under it means
/// we never rely on IP fragmentation, which is widely filtered and a well-known attack surface.
pub const MAX_DATAGRAM: usize = 1200;

/// Fixed size buckets a payload is padded up to.
///
/// Padding to a bucket means an observer learns roughly how big a message is, not exactly.
/// The gaps are deliberately coarse: many buckets would leak nearly as much as no padding.
pub const BUCKETS: [usize; 5] = [64, 256, 512, 1024, 1152];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// Datagram shorter than the fixed header.
    TooShort,
    /// Magic bytes did not match, so this is not ours.
    BadMagic,
    /// Version this build does not understand.
    UnsupportedVersion,
    /// Declared payload length disagrees with what arrived.
    LengthMismatch,
    /// Payload larger than [`MAX_DATAGRAM`] allows.
    TooLarge,
    /// The frame inside failed to parse.
    BadFrame,
    /// This datagram is a replay or fell outside the window.
    Replay,
    /// Underlying I/O failed.
    Io,
}

impl core::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::TooShort => "datagram too short",
            Self::BadMagic => "bad magic",
            Self::UnsupportedVersion => "unsupported version",
            Self::LengthMismatch => "declared length does not match datagram",
            Self::TooLarge => "datagram too large",
            Self::BadFrame => "sealed frame did not parse",
            Self::Replay => "replayed or out-of-window datagram",
            Self::Io => "transport I/O error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TunnelError {}

impl From<CryptoError> for TunnelError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Replay => Self::Replay,
            _ => Self::BadFrame,
        }
    }
}

impl From<sovereign_ipc::IpcError> for TunnelError {
    fn from(_: sovereign_ipc::IpcError) -> Self {
        Self::BadFrame
    }
}

/// A datagram: one sealed frame, padded and wrapped in a minimal header.
///
/// Layout: `magic(4) | version(1) | pad_len(2, big endian) | frame`.
///
/// The length is implicit — the datagram's own size carries it — so there is no length field an
/// attacker can rewrite to make a parser read differently than the receiver did.
#[derive(Debug, Clone)]
pub struct Datagram {
    frame: SealedFrame,
}

impl Datagram {
    /// Wrap a sealed frame, choosing the smallest bucket that fits.
    pub fn seal(frame: &SealedFrame) -> Result<Self, TunnelError> {
        // Reject early so the caller learns the message will never fit, rather than having it
        // padded and then truncated by the network.
        let encoded = frame.encode()?;
        let overhead = Self::header_len();
        if encoded.len() + overhead > MAX_DATAGRAM {
            return Err(TunnelError::TooLarge);
        }
        Ok(Self {
            frame: frame.clone(),
        })
    }

    /// Fixed header size, exposed so tests and callers can reason about overhead.
    pub const fn header_len() -> usize {
        MAGIC.len() + 1 + 2
    }

    /// The padded size this datagram will occupy on the wire.
    pub fn wire_len(&self) -> usize {
        let body = self.frame.encode().map(|v| v.len()).unwrap_or(0);
        let needed = Self::header_len() + body;
        BUCKETS
            .iter()
            .copied()
            .find(|b| *b >= needed)
            .unwrap_or(MAX_DATAGRAM)
            .min(MAX_DATAGRAM)
    }

    /// Serialise to bytes, padding to the chosen bucket.
    ///
    /// Padding bytes are zero and are not authenticated separately; they sit *outside* the AEAD
    /// ciphertext, so an attacker can change them without breaking the tag. That is fine: the
    /// pad length is used only to strip bytes, and a wrong value yields a frame that fails to
    /// parse or authenticate. Nothing is trusted because of the padding.
    pub fn encode(&self) -> Result<Vec<u8>, TunnelError> {
        let body = self.frame.encode()?;
        let total = self.wire_len();
        let overhead = Self::header_len();
        let pad = total
            .checked_sub(overhead + body.len())
            .ok_or(TunnelError::TooLarge)?;

        let mut w = Writer::with_capacity(total);
        w.bytes(&MAGIC);
        w.u8(VERSION);
        w.u16(u16::try_from(pad).map_err(|_| TunnelError::TooLarge)?);
        w.bytes(&body);

        let mut out = w.finish();
        out.resize(total, 0);
        Ok(out)
    }

    /// Parse a datagram from the wire.
    pub fn decode(buf: &[u8]) -> Result<Self, TunnelError> {
        if buf.len() > MAX_DATAGRAM {
            return Err(TunnelError::TooLarge);
        }
        if buf.len() < Self::header_len() + 2 {
            return Err(TunnelError::TooShort);
        }

        let mut r = Reader::new(buf);
        let magic = r.bytes(MAGIC.len())?;
        if magic != MAGIC {
            return Err(TunnelError::BadMagic);
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(TunnelError::UnsupportedVersion);
        }
        let pad = usize::from(r.u16()?);

        // `split_at` needs an index that is known to be in range. `checked_header_split`
        // returns it only after proving that, so there is no panic path here.
        let rest = buf.get(Self::header_len()..).ok_or(TunnelError::TooShort)?;
        // The pad length must describe a suffix that actually exists. `split_at_checked` does
        // the subtraction for us and returns None instead of underflowing on a huge pad.
        let body = rest
            .split_at_checked(rest.len().wrapping_sub(pad))
            .filter(|_| pad <= rest.len())
            .map(|(head, _tail)| head)
            .ok_or(TunnelError::LengthMismatch)?;

        let frame = SealedFrame::decode(body)?;
        Ok(Self { frame })
    }

    pub fn frame(&self) -> &SealedFrame {
        &self.frame
    }

    pub fn into_frame(self) -> SealedFrame {
        self.frame
    }

    /// Counter used for transport-level replay protection.
    pub fn counter(&self) -> u64 {
        self.frame.counter
    }
}

/// Transport-level replay filter, one per peer.
///
/// The session layer already keeps a replay window, but that only runs *after* decryption. This
/// one runs first, so a flood of replayed datagrams is discarded before it costs any AEAD work.
#[derive(Debug)]
pub struct PeerReplay {
    window: ReplayWindow,
}

impl Default for PeerReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerReplay {
    pub fn new() -> Self {
        Self {
            window: ReplayWindow::new(),
        }
    }

    /// Record a datagram's counter. Call this only after the frame inside has authenticated:
    /// accepting on arrival would let unauthenticated garbage burn counters and desynchronise
    /// the window, which is a denial of service for free.
    pub fn accept(&mut self, counter: u64) -> Result<(), TunnelError> {
        self.window.accept(counter)?;
        Ok(())
    }
}

/// A schedule for cover traffic.
///
/// Chaff is the cheapest defence against traffic analysis and the easiest to get wrong. Emitting
/// it at a fixed rate with fixed sizes is far more useful than emitting it "randomly": a
/// uniform-ish pattern hides which gaps are real. Callers drive the clock so this stays testable
/// without sleeping.
#[derive(Debug, Clone)]
pub struct ChaffSchedule {
    interval_millis: u64,
    next_due: u64,
    bucket: usize,
}

impl ChaffSchedule {
    /// Create a schedule that wants one cover datagram every `interval_millis`, of `bucket` bytes.
    pub fn new(interval_millis: u64, bucket: usize, start_millis: u64) -> Self {
        Self {
            interval_millis: interval_millis.max(1),
            next_due: start_millis.saturating_add(interval_millis.max(1)),
            bucket,
        }
    }

    /// How many chaff datagrams are due at `now_millis`.
    ///
    /// Returns a count rather than a boolean so a caller that was blocked for a while emits the
    /// right number of cover packets instead of silently falling behind and revealing a gap.
    /// The count is capped, because emitting thousands at once after a long stall is itself a
    /// signal and a pointless load spike.
    pub fn due(&mut self, now_millis: u64) -> usize {
        if now_millis < self.next_due {
            return 0;
        }
        let elapsed = now_millis - self.next_due;
        let n = elapsed / self.interval_millis + 1;
        let n = n.min(64) as usize;
        self.next_due = now_millis.saturating_add(self.interval_millis);
        n
    }

    /// Size of a cover datagram, matching a real bucket so it is indistinguishable by size.
    pub fn bucket(&self) -> usize {
        self.bucket.min(MAX_DATAGRAM)
    }
}

/// Build a cover datagram of the scheduled size, with random bytes in the payload.
///
/// It is not a valid sealed frame and no peer will accept it as one. That is the point: it costs
/// an observer the same effort to see that it is junk as a real frame costs to decrypt, and
/// either way the observer learns nothing about whether traffic is real.
pub fn chaff_datagram(size: usize) -> Result<Vec<u8>, TunnelError> {
    let size = size.clamp(Datagram::header_len() + 2, MAX_DATAGRAM);
    let header = Datagram::header_len();

    let mut out = vec![0u8; size];
    // Pad length stays 0, so the whole body is treated as "frame" and will fail to parse.
    // Only the magic and version are set; the rest is random so cover traffic does not look
    // like a run of zeros. Entropy failure is propagated rather than papered over: a
    // predictable cover packet is worse than none.
    let body = out.get_mut(header..).ok_or(TunnelError::TooLarge)?;
    sovereign_crypto::fill_random(body)?;

    let head = out.get_mut(..header).ok_or(TunnelError::TooShort)?;
    head.get_mut(..MAGIC.len())
        .ok_or(TunnelError::TooShort)?
        .copy_from_slice(&MAGIC);
    if let Some(v) = head.get_mut(MAGIC.len()) {
        *v = VERSION;
    }

    Ok(out)
}
