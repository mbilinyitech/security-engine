//! Stealth transport framing: fixed-size cells, pseudorandom padding, cover
//! cells, deterministic jitter and batching.
//!
//! The cell itself is sealed by the caller (ChaCha20-Poly1305 in the Python
//! layer), so padding only has to be indistinguishable *after* encryption. The
//! generator is deterministic on purpose: the Python port produces byte-for-byte
//! the same cells, and both are checked against the same known-answer vectors.

use std::fmt;

pub const COVER_MARKER: u32 = u32::MAX;
pub const DEFAULT_CELL: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthError {
    CellTooSmall,
    PayloadTooLarge { payload: usize, capacity: usize },
    Malformed,
}

impl fmt::Display for StealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StealthError::CellTooSmall => write!(formatter, "a cell needs at least 8 bytes"),
            StealthError::PayloadTooLarge { payload, capacity } => {
                write!(formatter, "payload of {payload} does not fit in {capacity} bytes")
            }
            StealthError::Malformed => write!(formatter, "the cell is malformed"),
        }
    }
}

impl std::error::Error for StealthError {}

#[derive(Debug, Clone)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn fill(&mut self, count: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(count);
        while output.len() < count {
            output.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        output.truncate(count);
        output
    }
}

pub fn frame(payload: &[u8], cell: usize, seed: u64) -> Result<Vec<u8>, StealthError> {
    if cell < 8 {
        return Err(StealthError::CellTooSmall);
    }
    let capacity = cell - 4;
    if payload.len() > capacity {
        return Err(StealthError::PayloadTooLarge {
            payload: payload.len(),
            capacity,
        });
    }
    let mut out = Vec::with_capacity(cell);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&XorShift64::new(seed).fill(cell - out.len()));
    Ok(out)
}

pub fn unframe(cell: &[u8]) -> Result<Option<Vec<u8>>, StealthError> {
    if cell.len() < 8 {
        return Err(StealthError::Malformed);
    }
    let declared = u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]);
    if declared == COVER_MARKER {
        return Ok(None);
    }
    let length = declared as usize;
    if length > cell.len() - 4 {
        return Err(StealthError::Malformed);
    }
    Ok(Some(cell[4..4 + length].to_vec()))
}

pub fn cover(cell: usize, seed: u64) -> Result<Vec<u8>, StealthError> {
    if cell < 8 {
        return Err(StealthError::CellTooSmall);
    }
    let mut out = Vec::with_capacity(cell);
    out.extend_from_slice(&COVER_MARKER.to_be_bytes());
    out.extend_from_slice(&XorShift64::new(seed).fill(cell - 4));
    Ok(out)
}

pub fn jitter_ms(seed: u64, index: u64, base_ms: u64, spread_ms: u64) -> u64 {
    let mixed = seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    base_ms + (XorShift64::new(mixed).next_u64() % (spread_ms + 1))
}

pub fn batch<T: Clone>(items: &[T], size: usize) -> Vec<Vec<T>> {
    if size == 0 {
        return Vec::new();
    }
    items.chunks(size).map(|chunk| chunk.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn frame_matches_the_python_vector() {
        let cell = frame(b"hi", 16, 7).expect("frame");
        assert_eq!(hex(&cell), "0000000268698b5e0c29b0abdb1c34a3");
    }

    #[test]
    fn cover_matches_the_python_vector() {
        let cell = cover(16, 7).expect("cover");
        assert_eq!(hex(&cell), "ffffffff8b5e0c29b0abdb1c34a39b1a");
    }

    #[test]
    fn jitter_matches_the_python_vector() {
        assert_eq!(jitter_ms(3, 0, 50, 250), 244);
        assert_eq!(jitter_ms(3, 1, 50, 250), 255);
    }

    #[test]
    fn round_trip_keeps_the_payload() {
        let cell = frame(b"the quick brown fox", DEFAULT_CELL, 42).expect("frame");
        assert_eq!(cell.len(), DEFAULT_CELL);
        assert_eq!(unframe(&cell).expect("unframe"), Some(b"the quick brown fox".to_vec()));
    }

    #[test]
    fn cover_unframes_to_none() {
        let cell = cover(DEFAULT_CELL, 9).expect("cover");
        assert_eq!(unframe(&cell).expect("unframe"), None);
    }

    #[test]
    fn oversized_payloads_are_refused() {
        let error = frame(&[0u8; 600], 512, 1).expect_err("must fail");
        assert_eq!(error, StealthError::PayloadTooLarge { payload: 600, capacity: 508 });
        assert_eq!(frame(b"x", 4, 1).expect_err("small"), StealthError::CellTooSmall);
    }

    #[test]
    fn padding_is_deterministic_and_seed_dependent() {
        let first = frame(b"same", 64, 5).expect("frame");
        let second = frame(b"same", 64, 5).expect("frame");
        let third = frame(b"same", 64, 6).expect("frame");
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn batching_splits_with_a_short_tail() {
        assert_eq!(batch(&[1, 2, 3, 4, 5], 2), vec![vec![1, 2], vec![3, 4], vec![5]]);
        assert!(batch(&[1, 2], 0).is_empty());
    }
}
