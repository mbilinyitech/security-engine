#!/bin/sh
# Boot the bare-metal kernel in QEMU and assert what it printed.
#
# A kernel that "compiles" proves nothing. This script is the only claim of correctness: it
# boots the image, captures the serial log, and fails if any expected line is missing. Deleting a
# gate check from main.rs changes the log and fails this script.
#
# Usage: ./run.sh          boot and assert
#        ./run.sh --keep   also leave the log at target/boot.log
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

kernel=target/x86_64-unknown-none/release/sovereign-kernel
log=${here}/target/boot.log
mkdir -p "${here}/target"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "FAIL: qemu-system-x86_64 not installed" >&2
    exit 1
fi

cargo build --release --quiet --target x86_64-unknown-none

# `-serial file:` rather than `-nographic`: with stdin redirected, `-nographic` multiplexes the
# monitor onto stdio and the guest's serial output is lost. Writing straight to a file is
# deterministic, and QEMU's own stderr is discarded so a missing QEMU is the only thing that can
# produce an empty log.
#
# `timeout` is expected to kill QEMU: the kernel halts and never exits on its own, so the exit
# status is not checked. The log is.
rm -f "$log"
timeout 15 qemu-system-x86_64 \
    -kernel "$kernel" \
    -display none \
    -serial "file:$log" \
    -no-reboot \
    </dev/null >/dev/null 2>&1 || true

# QEMU writes CRLF on the serial line.
clean=$(tr -d '\r' <"$log")

fail=0
expect() {
    if printf '%s\n' "$clean" | grep -qxF "$1"; then
        printf 'ok   %s\n' "$1"
    else
        printf 'FAIL missing: %s\n' "$1"
        fail=$((fail + 1))
    fi
}

# Boot path: the image must reach long mode, and must know which loader started it.
expect "sovereign-kernel: long mode entered"
expect "boot: PVH loader confirmed"

# The gate's own behaviour, one line per property.
expect "gate: valid token admitted ... ok"
expect "gate: replay refused ... ok"
expect "gate: expired token refused ... ok"
expect "gate: quarantined device refused ... ok"
expect "gate: revoked device refused ... ok"
expect "gate: reserved rights refused ... ok"
expect "gate: short token refused ... ok"
expect "gate: least privilege enforced ... ok"

# The aggregate counters, so a dropped check cannot pass by being absent.
expect "gate: 8 passed, 0 failed"
expect "RESULT: PASS"

# A panic must not appear anywhere in a healthy boot.
if printf '%s\n' "$clean" | grep -q "KERNEL PANIC"; then
    printf 'FAIL kernel panicked\n'
    fail=$((fail + 1))
fi

if [ "$fail" -ne 0 ]; then
    echo "---- boot log ----"
    printf '%s\n' "$clean"
    echo "FAIL: $fail assertion(s) failed"
    exit 1
fi

echo "PASS: kernel booted and all gate assertions held"
