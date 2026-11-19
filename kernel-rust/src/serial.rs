//! Serial console on COM1, polled.
//!
//! Polled rather than interrupt-driven on purpose: an interrupt handler needs an IDT, a PIC or
//! APIC setup, and a working stack per privilege level. None of that is needed to prove the
//! kernel boots and runs the gate, and every one of them is a way to hang before the first line
//! of output appears. A kernel you cannot see boot is a kernel you cannot debug.

use core::arch::asm;

const COM1: u16 = 0x3F8;

// UART register offsets. The divisor latch shares offsets 0 and 1 with the data and interrupt
// registers, selected by DLAB in the line control register — which is why `init` writes to the
// same port twice with different meanings.
const DATA: u16 = 0;
const IER: u16 = 1;
const FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const DLL: u16 = 0;
const DLM: u16 = 1;

/// Initialise COM1 to 115200 8N1 with FIFOs enabled.
///
/// # Safety
///
/// Performs port I/O. Only sound once we are in long mode with the port accessible, which is the
/// case by the time `_start` calls this.
pub unsafe fn init() {
    outb(COM1 + IER, 0x00); // no interrupts
    outb(COM1 + LCR, 0x80); // DLAB on: offsets 0 and 1 now mean divisor
    outb(COM1 + DLL, 0x01); // divisor 1 -> 115200 baud
    outb(COM1 + DLM, 0x00);
    outb(COM1 + LCR, 0x03); // DLAB off, 8 bits, no parity, one stop
    outb(COM1 + FCR, 0xC7); // FIFO on, cleared, 14-byte threshold
    outb(COM1 + MCR, 0x0B); // IRQs off, RTS/DSR set
}

unsafe fn outb(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

fn line_ready() -> bool {
    // SAFETY: reading the line status register of an initialised UART has no side effects.
    unsafe { inb(COM1 + LSR) & 0x20 != 0 }
}

pub fn write_byte(b: u8) {
    // Spin with a bound instead of forever. If the UART is absent (a machine with no COM1), an
    // unbounded wait would hang the kernel before it could report anything; giving up lets the
    // rest of the boot continue silently.
    for _ in 0..100_000 {
        if line_ready() {
            // SAFETY: transmitter is ready, so this write cannot be dropped.
            unsafe { outb(COM1 + DATA, b) };
            return;
        }
        core::hint::spin_loop();
    }
}

pub fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// A `fmt::Write` adapter so `write!` works without allocating.
pub struct Serial;

impl core::fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = write!($crate::serial::Serial, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::serial::write_str("\n") };
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = write!($crate::serial::Serial, $($arg)*);
        $crate::serial::write_str("\n");
    }};
}
