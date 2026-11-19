//! Sliding-window replay protection for sealed frames.
//!
//! The same construction as IPsec anti-replay (RFC 4303 §3.4.3), with the window size as a
//! compile-time constant. A frame is accepted at most once; frames older than the window are
//! refused outright, which bounds memory regardless of how long an attacker replays.
//!
//! This matters because the stealth tunnel is unreliable and reorders freely: a strict
//! "counter must equal last+1" rule would drop legitimate traffic, while "counter > last"
//! alone would let an attacker replay anything within the window.

use crate::CryptoError;

/// 2048 bits = 2048 frames of tolerance. Enough for any realistic reorder depth on a lossy
/// radio link, and only 256 bytes of state.
pub const WINDOW_BITS: u64 = 2048;

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest counter accepted so far. `None` until the first frame.
    high: Option<u64>,
    /// Bitmap of accepted counters below `high`. Bit 0 is `high - 1`.
    bitmap: [u64; (WINDOW_BITS / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            high: None,
            bitmap: [0u64; (WINDOW_BITS / 64) as usize],
        }
    }

    pub fn high_water_mark(&self) -> Option<u64> {
        self.high
    }

    /// Check and record `counter`. Returns `Err(Replay)` if the counter was already seen or
    /// has fallen out of the window.
    pub fn accept(&mut self, counter: u64) -> Result<(), CryptoError> {
        let Some(high) = self.high else {
            self.high = Some(counter);
            return Ok(());
        };

        if counter > high {
            self.advance(counter);
            return Ok(());
        }

        let delta = high - counter;
        // delta == 0 means the counter equals the high-water mark, which by definition was
        // already accepted. Otherwise bit `delta - 1` records it, because bit 0 is `high - 1`.
        if delta == 0 || delta >= WINDOW_BITS {
            return Err(CryptoError::Replay);
        }
        let bit = (delta - 1) as usize;
        let mask = 1u64 << (bit % 64);
        if self.bitmap[bit / 64] & mask != 0 {
            return Err(CryptoError::Replay);
        }
        self.bitmap[bit / 64] |= mask;
        Ok(())
    }

    /// Slide the window forward to `new_high`, then record the old high-water mark, which now
    /// sits at bit `shift - 1`.
    fn advance(&mut self, new_high: u64) {
        let prev = self.high.unwrap_or(0);
        let shift = new_high - prev;
        self.high = Some(new_high);

        if shift >= WINDOW_BITS {
            // The old high-water mark, and everything below it, has fallen out of the window.
            // Counters still inside the window were never seen, so every bit stays clear.
            self.bitmap = [0u64; (WINDOW_BITS / 64) as usize];
            return;
        }

        self.shift_left(shift as usize);
        let bit = (shift - 1) as usize;
        self.bitmap[bit / 64] |= 1u64 << (bit % 64);
    }

    /// Shift the bitmap left by `shift` bits, where bit 0 is the most recent counter.
    fn shift_left(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        let words = (WINDOW_BITS / 64) as usize;
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift >= words {
            self.bitmap = [0u64; (WINDOW_BITS / 64) as usize];
            return;
        }

        let mut out = [0u64; (WINDOW_BITS / 64) as usize];
        for i in (0..words).rev() {
            let src = i as isize - word_shift as isize;
            if src < 0 {
                break;
            }
            let src = src as usize;
            out[i] = self.bitmap[src] << bit_shift;
            if bit_shift > 0 && src > 0 {
                out[i] |= self.bitmap[src - 1] >> (64 - bit_shift);
            }
        }
        self.bitmap = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order() {
        let mut w = ReplayWindow::new();
        for i in 1..=100u64 {
            w.accept(i).expect("in-order");
        }
        // The whole point of the window: every one of those counters is now burned.
        for i in 1..=100u64 {
            assert!(w.accept(i).is_err(), "counter {i} must not replay");
        }
    }

    #[test]
    fn rejects_exact_replay() {
        let mut w = ReplayWindow::new();
        w.accept(5).expect("first");
        assert_eq!(w.accept(5).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        w.accept(10).expect("first");
        w.accept(8).expect("reorder");
        w.accept(9).expect("reorder");
        assert_eq!(w.accept(8).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn rejects_below_window() {
        let mut w = ReplayWindow::new();
        w.accept(1).expect("first");
        w.accept(1 + WINDOW_BITS).expect("advance");
        // Counter 1 is now exactly WINDOW_BITS below the high mark: outside the window.
        assert_eq!(w.accept(1).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn accepts_just_inside_window() {
        let mut w = ReplayWindow::new();
        w.accept(1).expect("first");
        w.accept(1 + WINDOW_BITS - 1).expect("advance");
        // Distance from high is WINDOW_BITS - 2, inside the window, and never seen.
        w.accept(2).expect("inside window");
        // But it can only be used once.
        assert!(w.accept(2).is_err(), "replay of an in-window counter");
    }

    #[test]
    fn large_jump_clears_history() {
        let mut w = ReplayWindow::new();
        w.accept(1).expect("first");
        w.accept(10_000).expect("jump");
        assert_eq!(w.accept(1).unwrap_err(), CryptoError::Replay);
        assert_eq!(w.accept(9_999).expect("just below"), ());
        assert_eq!(w.accept(9_999).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn window_boundaries_do_not_panic() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("zero");
        w.accept(u64::MAX).expect("max");
        assert_eq!(w.accept(u64::MAX).unwrap_err(), CryptoError::Replay);
    }

    #[test]
    fn every_offset_in_window_round_trips() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("first");
        w.accept(WINDOW_BITS).expect("advance to window edge");
        for c in 1..WINDOW_BITS {
            w.accept(c).expect("each counter inside the window once");
        }
        for c in 1..WINDOW_BITS {
            assert_eq!(w.accept(c).unwrap_err(), CryptoError::Replay);
        }
    }
}
