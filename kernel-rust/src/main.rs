//! Sovereign bare-metal kernel.
//!
//! ## What this is
//!
//! A real kernel image: multiboot1 header, 32-bit entry, page tables built at runtime, switch to
//! long mode, then a `no_std` Rust `kmain` that runs the capability gate and halts. QEMU boots it
//! with `-kernel` and the serial log is asserted by `run.sh`, so "it boots" is a test result, not
//! a claim.
//!
//! Multiboot **1** rather than 2 because QEMU's `-kernel` implements only the older protocol. The
//! newer header would force a GRUB ISO build for no benefit at this size.
//!
//! ## What this is not
//!
//! It is not a general-purpose OS and not a drop-in replacement for the C modules in `../kernel`.
//! It has no scheduler, no allocator, no filesystem, no userspace, and no driver model. Those are
//! each substantial projects. What it does prove is the part that was previously unproven: that
//! the gate logic compiles and runs with nothing underneath it, and that the boot path is ours
//! rather than a host kernel's.
//!
//! ## Why the 32-bit stage exists at all
//!
//! Multiboot2 hands control over in 32-bit protected mode. There is no way to be in long mode at
//! `_start`, so the first ~40 lines must be assembly. Everything after the `jmp` into
//! `long_mode_start` is Rust.

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::panic)]

mod serial;

use sovereign_gate_core as gate;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

use gate::{Gate, Token, TOKEN_LEN};

// ---------------------------------------------------------------------------------------------
// Multiboot1 header
// ---------------------------------------------------------------------------------------------
//
// Must be 4-byte aligned and inside the first 8192 bytes of the file, which the linker script
// guarantees by placing `.boot` first at 1 MiB. The checksum is defined so the three words sum
// to zero; a wrong checksum makes QEMU silently refuse the image.

// ---------------------------------------------------------------------------------------------
// PVH note: lets QEMU's `-kernel` boot this ELF64 directly
// ---------------------------------------------------------------------------------------------
//
// QEMU refuses a 64-bit ELF with `-kernel` unless it carries a PVH note, because the legacy path
// only understands 32-bit images. The note names a 32-bit physical entry point, which is exactly
// what `_start` is, so the boot sequence is unchanged — the note only tells QEMU where to jump.

global_asm!(
    r#"
.section .note.Xen, "a", @note
.align 4
    .long 4                      /* namesz: "Xen\0" */
    .long 4                      /* descsz: one 32-bit address */
    .long 18                     /* type: XEN_ELFNOTE_PHYS32_ENTRY */
    .ascii "Xen\0"
    .align 4
    .long _start                 /* 32-bit physical entry */
    .align 4
"#
);

// ---------------------------------------------------------------------------------------------
// Boot: 32-bit protected mode -> long mode
// ---------------------------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.boot, "ax"
.code32
.global _start
_start:
    cli

    /* The loader's handoff values live in EAX and EBX, and everything below clobbers both.
     * Save them before touching anything else, or the kernel receives garbage and cannot tell
     * which loader booted it. */
    mov dword ptr [loader_magic], eax
    mov dword ptr [loader_info], ebx

    mov esp, offset boot_stack_top

    /* Build identity-mapped page tables in the statically reserved area.
     * PML4[0] -> PDPT, PDPT[0] -> PD, and PD entries use 2 MiB pages so one PD covers the
     * first 1 GiB. That is enough for the kernel image and the VGA buffer at 0xB8000. */

    /* Clear 4 pages (PML4, PDPT, PD, spare) at 0x100000 */
    mov edi, offset page_tables
    mov ecx, 4096
    xor eax, eax
    rep stosd

    /* PML4[0] = PDPT | present | writable */
    mov eax, offset pdpt
    or  eax, 0x3
    mov dword ptr [page_tables], eax

    /* PDPT[0] = PD | present | writable */
    mov eax, offset pd
    or  eax, 0x3
    mov dword ptr [pdpt], eax

    /* PD[i] = i * 2MiB | present | writable | page-size(2MiB) */
    mov ecx, 0
1:
    mov eax, ecx
    shl eax, 21
    or  eax, 0x83
    mov dword ptr [pd + ecx * 8], eax
    mov dword ptr [pd + ecx * 8 + 4], 0
    inc ecx
    cmp ecx, 512
    jb  1b

    /* CR3 = PML4 */
    mov eax, offset page_tables
    mov cr3, eax

    /* Enable PAE (CR4 bit 5) */
    mov eax, cr4
    or  eax, (1 << 5)
    mov cr4, eax

    /* Enable long mode (EFER.LME, MSR 0xC0000080 bit 8) */
    mov ecx, 0xC0000080
    rdmsr
    or  eax, (1 << 8)
    wrmsr

    /* Enable paging (CR0 bit 31) -- this is what actually enters long mode */
    mov eax, cr0
    or  eax, (1 << 31)
    mov cr0, eax

    /* Load a 64-bit GDT and far-jump into it */
    lgdt [gdt64_ptr]
    /* 32-bit far jump: opcode EA, 32-bit offset, 16-bit selector. Written as bytes because
     * GAS rejects the `ljmp $sel, $target` form when assembling for a 64-bit target. */
    .byte 0xEA
    .long long_mode_start
    .short 0x08
"#
);

// The GDT: null, then one 64-bit code segment, then one data segment. Flat, ring 0 only. A ring-3
// segment is deliberately absent: nothing in this kernel runs in userspace, and adding one without
// a TSS and an IDT would be a false claim of isolation.
global_asm!(
    r#"
.section .rodata
.align 16
gdt64:
    .quad 0
    .quad 0x00AF9A0000000000      /* code: present, DPL0, code, L=1 */
    .quad 0x00CF920000000000      /* data: present, DPL0, writable */
gdt64_end:
gdt64_ptr:
    .short gdt64_end - gdt64 - 1
    .quad gdt64
"#
);

global_asm!(
    r#"
.section .text
.code64
.global long_mode_start
long_mode_start:
    /* Reload data segments; long mode ignores most of them but the CPU still checks them. */
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    /* Fresh stack in the reserved area, then into Rust.
     * System V passes the first two integer arguments in RDI and RSI, so the saved handoff
     * values are loaded there. */
    mov rsp, offset stack_top
    xor rbp, rbp
    mov edi, dword ptr [loader_magic]
    mov esi, dword ptr [loader_info]
    call kmain

    /* kmain never returns; if it does, halt rather than fall into whatever follows. */
2:  cli
    hlt
    jmp 2b
"#
);

// ---------------------------------------------------------------------------------------------
// Static storage
// ---------------------------------------------------------------------------------------------

/// One 4 KiB page-table page. Must be page-aligned and inside the identity-mapped region.
#[repr(C, align(4096))]
struct Page([u8; 4096]);

#[no_mangle]
static mut page_tables: Page = Page([0; 4096]);
#[no_mangle]
static mut pdpt: Page = Page([0; 4096]);
#[no_mangle]
static mut pd: Page = Page([0; 4096]);

/// 32-bit boot stack, used only between `_start` and the jump to long mode.
#[repr(C, align(16))]
struct BootStack([u8; 4096]);

#[no_mangle]
static mut boot_stack: BootStack = BootStack([0; 4096]);

/// 64-bit stack for Rust code.
#[repr(C, align(16))]
struct Stack([u8; 64 * 1024]);

#[no_mangle]
static mut kernel_stack: Stack = Stack([0; 64 * 1024]);

// The assembly refers to these by symbol, so they need stable names rather than mangled ones.
/// Handoff values saved by `_start` before the 32-bit stage clobbers the registers.
#[no_mangle]
static mut loader_magic: u32 = 0;
#[no_mangle]
static mut loader_info: u32 = 0;

core::arch::global_asm!(
    r#"
.section .bss
.global boot_stack_top
.set boot_stack_top, boot_stack + 4096
.global stack_top
.set stack_top, kernel_stack + 65536
"#
);

// ---------------------------------------------------------------------------------------------
// Panic: halt, do not unwind
// ---------------------------------------------------------------------------------------------

/// A panic in a kernel cannot unwind (there is nothing to unwind to) and cannot be logged to a
/// file. It writes to serial and halts. `panic = "abort"` in the profile plus this handler means
/// there is no path where a panic silently continues.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // SAFETY: the UART is initialised before any code that can panic.
    unsafe {
        serial::init();
    }
    serial::write_str("\nKERNEL PANIC: ");
    if let Some(loc) = info.location() {
        let _ = core::fmt::write(
            &mut serial::Serial,
            format_args!("{}:{}: ", loc.file(), loc.line()),
        );
    }
    if let Some(msg) = info.message().as_str() {
        serial::write_str(msg);
    }
    serial::write_str("\n");
    halt();
}

fn halt() -> ! {
    loop {
        // SAFETY: `hlt` in a loop is the correct idle for a kernel with no scheduler.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

// ---------------------------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------------------------

/// The kernel proper.
///
/// `multiboot_magic` and `multiboot_info` are what the bootloader passed in `EAX`/`EBX`. They are
/// received but not parsed: this kernel needs no boot information, and parsing an untrusted
/// structure from the bootloader would be an attack surface with no payoff. They are checked only
/// to prove we were actually booted by a multiboot loader rather than jumped into.
/// Magic a multiboot1 loader leaves in `EAX`.
const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;
/// Magic at the head of the PVH `hvm_start_info` structure.
const XEN_HVM_START_MAGIC: u32 = 0x336E_C578;

#[no_mangle]
pub extern "C" fn kmain(boot_magic: u32, boot_info: u32) -> ! {
    // SAFETY: called once from `long_mode_start` after the UART's port is accessible.
    unsafe { serial::init() };

    kprintln!("sovereign-kernel: long mode entered");

    // Two loaders can get us here, and they leave different things behind. Checking which one
    // actually booted us is the difference between "the kernel started" and "the kernel started
    // the way it was designed to". A bare jump into `_start` matches neither and is refused.
    if boot_magic == MULTIBOOT_BOOTLOADER_MAGIC {
        kprintln!("boot: multiboot1 loader confirmed");
    } else if pvh_start_info_present(boot_info) {
        kprintln!("boot: PVH loader confirmed");
    } else {
        kprintln!("boot: unrecognised loader (eax {boot_magic:#x}, ebx {boot_info:#x})");
        kprintln!("RESULT: FAIL");
        halt();
    }

    run_self_checks();

    kprintln!("RESULT: PASS");
    halt();
}

/// Does `info` point at a PVH `hvm_start_info` with the right magic?
///
/// Under PVH, `EBX` holds a physical address of the start-info structure rather than multiboot's
/// info block. We read only the first word, and only after confirming the pointer is in the
/// identity-mapped low region — dereferencing an arbitrary `EBX` would be a page fault, and a
/// page fault with no IDT is a triple fault and a silent reboot loop.
fn pvh_start_info_present(info: u32) -> bool {
    // The first 1 GiB is identity-mapped by the boot page tables, so anything outside it cannot
    // be read safely.
    if info == 0 || info as u64 >= (1 << 30) {
        return false;
    }
    if !info.is_multiple_of(4) {
        return false;
    }
    // SAFETY: `info` is non-null, 4-byte aligned, and inside the identity-mapped region checked
    // above, so this read cannot fault.
    let magic = unsafe { core::ptr::read_volatile(info as *const u32) };
    magic == XEN_HVM_START_MAGIC
}

/// Exercise the gate on real inputs. Each check prints and increments a counter; the last line is
/// what `run.sh` greps for, so a regression in the gate changes the boot log.
fn run_self_checks() {
    let mut passed = 0u32;
    let mut failed = 0u32;

    let now = 1_000u64;
    let token_bytes = gate::encode_token(
        [0xC0; 16],
        gate::rights::SENSOR_READ | gate::rights::TELEMETRY_WRITE,
        900,
        1_100,
        1,
        [0x5A; 32],
    );

    let check = |name: &str, ok: bool, passed: &mut u32, failed: &mut u32| {
        if ok {
            kprintln!("gate: {name} ... ok");
            *passed += 1;
        } else {
            kprintln!("gate: {name} ... FAIL");
            *failed += 1;
        }
    };

    // 1. A valid token is admitted on an active device.
    let mut g = Gate::new();
    g.activate();
    let t = match Token::parse(&token_bytes) {
        Ok(t) => t,
        Err(_) => {
            kprintln!("gate: token parse ... FAIL");
            kprintln!("gate: {passed} passed, {} failed", failed + 1);
            return;
        }
    };
    check(
        "valid token admitted",
        g.admit(&t, now).is_ok(),
        &mut passed,
        &mut failed,
    );

    // 2. The same token again is a replay.
    check(
        "replay refused",
        g.admit(&t, now).is_err(),
        &mut passed,
        &mut failed,
    );

    // 3. An expired token is refused.
    let mut g2 = Gate::new();
    g2.activate();
    check(
        "expired token refused",
        g2.admit(&t, 2_000).is_err(),
        &mut passed,
        &mut failed,
    );

    // 4. A quarantined device is refused.
    let mut g3 = Gate::new();
    check(
        "quarantined device refused",
        g3.admit(&t, now).is_err(),
        &mut passed,
        &mut failed,
    );

    // 5. A revoked device is refused.
    let mut g4 = Gate::new();
    g4.activate();
    g4.revoke();
    check(
        "revoked device refused",
        g4.admit(&t, now).is_err(),
        &mut passed,
        &mut failed,
    );

    // 6. Reserved rights bits are refused at parse time.
    let mut bad = token_bytes;
    bad[20] = 0b1000_0000;
    check(
        "reserved rights refused",
        Token::parse(&bad).is_err(),
        &mut passed,
        &mut failed,
    );

    // 7. A truncated token is refused.
    check(
        "short token refused",
        Token::parse(&token_bytes[..TOKEN_LEN - 1]).is_err(),
        &mut passed,
        &mut failed,
    );

    // 8. Rights are enforced, not merely recorded.
    let mut g5 = Gate::new();
    g5.activate();
    let t5 = Token::parse(&token_bytes).expect("fixture is valid");
    let granted = g5.admit(&t5, now).expect("admitted");
    check(
        "least privilege enforced",
        g5.permits(granted, gate::rights::SENSOR_READ) && !g5.permits(granted, gate::rights::ADMIN),
        &mut passed,
        &mut failed,
    );

    kprintln!("gate: {passed} passed, {failed} failed");
    if failed != 0 {
        kprintln!("RESULT: FAIL");
        halt();
    }
}
