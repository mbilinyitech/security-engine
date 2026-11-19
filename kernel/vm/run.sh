#!/bin/sh
# Boot the module in a real VM and prove it works.
#
# Why a VM: this container has no CAP_SYS_MODULE, so `insmod` returns EPERM here. The only way
# to test device registration, file_operations, copy_from_user, and the kernel's own hmac(sha256)
# is to boot a kernel that will actually load the module. QEMU with TCG needs no /dev/kvm.
#
# What this proves, and what it does not:
#   * proves: the module loads, creates /dev/sovereign_gate, enforces every refusal path, accepts
#     a grant minted by sovereign-bridge, and unloads cleanly.
#   * does not prove: anything about IOMMU, DMA containment, or real hardware. There is no
#     device behind the chardev.
#
# Requirements: qemu-system-x86_64, a kernel image with matching headers, gcc, cpio, busybox.
# Override the kernel with KERNEL_IMAGE=... and KERNEL_BUILD=...

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
KERNEL_IMAGE=${KERNEL_IMAGE:-}
KERNEL_BUILD=${KERNEL_BUILD:-}

say() { printf '\n=== %s ===\n' "$1"; }

# --- locate a kernel and its headers -------------------------------------------------------
if [ -z "$KERNEL_BUILD" ]; then
for d in /lib/modules/*/build; do
[ -d "$d" ] && KERNEL_BUILD=$d && break
done
fi
[ -n "$KERNEL_BUILD" ] || { echo "no kernel headers found; set KERNEL_BUILD" >&2; exit 1; }

KVER=$(basename "$(dirname "$KERNEL_BUILD")")
if [ -z "$KERNEL_IMAGE" ]; then
KERNEL_IMAGE=/boot/vmlinuz-$KVER
fi
[ -f "$KERNEL_IMAGE" ] || {
echo "no kernel image at $KERNEL_IMAGE; set KERNEL_IMAGE" >&2
exit 1
}

say "kernel $KVER"
echo "image:  $KERNEL_IMAGE"
echo "build:  $KERNEL_BUILD"
echo "work:   $WORK"

# --- build the module against that kernel --------------------------------------------------
say "building module"
make -C "$ROOT/kernel" KDIR="$KERNEL_BUILD" >/dev/null
[ -f "$ROOT/kernel/sovereign_gate.ko" ] || { echo "module build failed" >&2; exit 1; }
[ -f "$ROOT/kernel/sov_mldsa.ko" ] || { echo "sov_mldsa.ko missing: run make -C kernel" >&2; exit 1; }

# --- mint a grant with the real bridge -----------------------------------------------------
# The grant carries an expiry, so it has to be minted at run time, not committed.
say "minting grant with sovereign-bridge"
BRIDGE=$ROOT/target/debug/sovereign-bridge
[ -x "$BRIDGE" ] || cargo build --manifest-path "$ROOT/Cargo.toml" -p sovereign-bridge >/dev/null

get() { grep "^$2=" "$1" | head -1 | cut -d= -f2-; }

"$BRIDGE" ca init > "$WORK/root.txt"
"$BRIDGE" ca init > "$WORK/dev.txt"
ROOT_SEED="$(get "$WORK/root.txt" root-ecdsa-seed):$(get "$WORK/root.txt" root-mldsa-seed)"
DEV_SEED="$(get "$WORK/dev.txt" root-ecdsa-seed):$(get "$WORK/dev.txt" root-mldsa-seed)"
DEV_PUB="$(get "$WORK/dev.txt" root-public-key)"
ROOT_PUB="$(get "$WORK/root.txt" root-public-key)"

"$BRIDGE" ca certify "$ROOT_SEED" "$DEV_PUB" sensor,telemetry > "$WORK/cert.txt"
CERT=$(get "$WORK/cert.txt" device-cert)

NONCE=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
"$BRIDGE" enroll "$ROOT_PUB" "$CERT" "$NONCE" "$DEV_SEED" > "$WORK/claim.txt"
ATT=$(get "$WORK/claim.txt" attestation)

SESSION=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
NOW=$(date +%s)
"$BRIDGE" host "$ROOT_SEED" "$CERT" "$NONCE" "$ATT" "$SESSION" "$NOW" > "$WORK/host.txt"
GRANT=$(get "$WORK/host.txt" grant)

# Re-verify exactly as the kernel-facing path would, so a broken grant fails here rather than
# confusingly inside the VM.
"$BRIDGE" verify "$ROOT_PUB" "$GRANT" "$NOW" >/dev/null

# The root key the module is loaded with. Must match what the bridge used to tag the grant.
ROOT_KEY=$(printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
"$BRIDGE" kernel-grant "$GRANT" "$ROOT_KEY" > "$WORK/blob.txt"
BLOB=$(head -1 "$WORK/blob.txt")
[ ${#BLOB} -eq 218 ] || { echo "blob is ${#BLOB} hex chars, expected 218" >&2; exit 1; }
echo "grant:  ${GRANT%"${GRANT#????????????????????????????????}"}..."
echo "blob:   109 bytes (77 token + 32 hmac tag)"

# v2: the same grant, but carrying its hybrid signature instead of an HMAC tag. The kernel
# verifies both halves itself, so it needs only the public keys below and cannot mint grants.
"$BRIDGE" kernel-grant-v2 "$GRANT" > "$WORK/blob_v2.txt"
BLOB_V2=$(head -1 "$WORK/blob_v2.txt")
[ ${#BLOB_V2} -eq 9618 ] || { echo "v2 blob is ${#BLOB_V2} hex chars, expected 9618" >&2; exit 1; }

# root-public-key is 97-byte SEC1 P-384 followed by the 2592-byte ML-DSA-87 key.
# POSIX sh has no substring expansion; cut the hex by character count.
ECDSA_PUB=$(printf '%s' "$ROOT_PUB" | cut -c1-194)
MLDSA_VK=$(printf '%s' "$ROOT_PUB" | cut -c195-)
[ ${#ECDSA_PUB} -eq 194 ] || { echo "ecdsa pub key is ${#ECDSA_PUB} hex chars" >&2; exit 1; }
[ ${#MLDSA_VK} -eq 5184 ] || { echo "mldsa vk is ${#MLDSA_VK} hex chars" >&2; exit 1; }
echo "grant:  ${GRANT%"${GRANT#????????????????????????????????}"}..."
echo "blob:   109 bytes (77 token + 32 hmac tag)"
echo "blob2:  $(( ${#BLOB_V2} / 2 )) bytes (5 header + 77 token + 2 + 96 ecdsa + 2 + 4627 mldsa)"

# --- stage the initramfs -------------------------------------------------------------------
say "staging initramfs"
STAGE=$WORK/stage
mkdir -p "$STAGE/bin" "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/tmp"
cp "$ROOT/kernel/sovereign_gate.ko" "$ROOT/kernel/sov_iommu.ko" "$ROOT/kernel/sov_mldsa.ko" \
   "$ROOT/kernel/sov_ecdsa.ko" "$ROOT/kernel/sov_hybrid.ko" "$STAGE/"
cp /bin/busybox "$STAGE/bin/" 2>/dev/null || cp /usr/bin/busybox "$STAGE/bin/"
for a in sh mount mknod cat dmesg poweroff; do ln -sf busybox "$STAGE/bin/$a"; done

python3 - "$BLOB" "$HERE" "$STAGE" <<'PY'
import sys, pathlib
blob_hex, here, stage = sys.argv[1], sys.argv[2], sys.argv[3]
b = bytes.fromhex(blob_hex)
lines = ['/* generated by run.sh from a live sovereign-bridge grant */',
         '#ifndef E2E_H', '#define E2E_H', '#include <stdint.h>', '',
         'static const uint8_t e2e_blob[109] = {']
for i in range(0, 109, 12):
    lines.append(','.join(str(x) for x in b[i:i+12]) + ',')
lines += ['};', '#endif']
pathlib.Path(stage, 'e2e.h').write_text('\n'.join(lines))
PY

python3 - "$BLOB_V2" "$STAGE" <<'PY2'
import sys, pathlib
blob_hex, stage = sys.argv[1], sys.argv[2]
b = bytes.fromhex(blob_hex)
lines = ['/* generated by run.sh from a live sovereign-bridge v2 grant */',
         '#ifndef E2E_V2_H', '#define E2E_V2_H', '#include <stdint.h>', '',
         'static const uint8_t e2e_v2_blob[%d] = {' % len(b)]
for i in range(0, len(b), 12):
    lines.append(','.join(str(x) for x in b[i:i+12]) + ',')
lines += ['};', '#endif']
pathlib.Path(stage, 'e2e_v2.h').write_text('\n'.join(lines))
PY2

gcc -static -O2 -Wall -I"$STAGE" -o "$STAGE/bin/vmt" "$HERE/vmt.c"
gcc -static -O2 -Wall -I"$STAGE" -o "$STAGE/bin/e2e_test" "$HERE/e2e_test.c"
gcc -static -O2 -Wall -Wextra -o "$STAGE/bin/iommu_test" "$HERE/iommu_test.c"
gcc -static -O2 -Wall -Wextra -I"$STAGE" -o "$STAGE/bin/e2e_v2_test" "$HERE/e2e_v2_test.c"

sed -e "s/@ROOT_KEY@/$ROOT_KEY/" -e "s/@ECDSA_PUB@/$ECDSA_PUB/" \
    -e "s/@MLDSA_VK@/$MLDSA_VK/" "$HERE/init.sh" > "$STAGE/init"
chmod +x "$STAGE/init"

( cd "$STAGE" && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$WORK/initramfs.gz" )

# --- boot ----------------------------------------------------------------------------------
say "booting"
LOG=$WORK/console.log
# -serial file: rather than shell redirection: with -nographic, QEMU writes the console to
# stdin/stdout, and a redirected stdout can be buffered away entirely.
timeout 300 qemu-system-x86_64 \
-machine q35 \
-m 512 \
-kernel "$KERNEL_IMAGE" \
-initrd "$WORK/initramfs.gz" \
-append "console=ttyS0 panic=-1 quiet intel_iommu=on iommu=pt" \
-device intel-iommu \
-device edu \
-display none -serial "file:$LOG" -monitor none -no-reboot >/dev/null 2>&1 || true

sed -n '/=== BOOTED/,$p' "$LOG"

# --- assert --------------------------------------------------------------------------------
say "verdict"
fail=0
check() {
if grep -q "$1" "$LOG"; then
echo "  ok   $2"
else
echo "  FAIL $2"
fail=1
fi
}
check 'insmod_exit=0' 'module loaded'
check 'RESULT: all passed' 'every gate test passed in-kernel'
check 'RESULT: end-to-end passed' 'kernel accepted a sovereign-bridge grant'
check 'rmmod_exit=0' 'module unloaded cleanly'
check 'iommu_insmod_exit=0' 'IOMMU module loaded'
check 'RESULT: iommu passed' 'IOMMU state machine behaves'
check 'sov_iommu: selftest passed' 'device DMA lands when mapped and is dropped when not'
check 'iommu_rmmod_exit=0' 'IOMMU module unloaded cleanly'
check 'sov_mldsa:   ok   valid signature accepted' 'kernel verified a Rust-signed ML-DSA-87 grant'
check 'sov_mldsa:   ok   corrupted signature rejected' 'kernel rejected a tampered ML-DSA-87 signature'
check 'sov_mldsa: selftest passed' 'ML-DSA-87 self-test passed in-kernel'
check 'mldsa_rmmod_exit=0' 'ML-DSA module unloaded cleanly'

check 'ecdsa_insmod_exit=0' 'ECDSA module loaded'
check 'sov_ecdsa: RESULT: selftest passed' 'kernel verified a Rust-signed ECDSA P-384 signature'
check 'sov_ecdsa:   ok   tampered signature rejected' 'kernel rejected a tampered ECDSA P-384 signature'
check 'hybrid_insmod_exit=0' 'hybrid module loaded'
check 'sov_hybrid: selftest passed' 'hybrid AND-composition verified in-kernel'
check 'sov_hybrid:   ok   cross-paired halves rejected' 'kernel rejected cross-paired signature halves'
check 'hybrid_rmmod_exit=0' 'hybrid module unloaded cleanly'
check 'RESULT: end-to-end v2 passed' 'kernel accepted a hybrid-signed grant end to end'
check 'RESULT: end-to-end v2 rejected tampered' 'kernel rejected a tampered hybrid-signed grant'

if [ "$fail" -ne 0 ]; then
echo
echo "console log kept at $LOG" >&2
exit 1
fi
echo
echo "VM verification passed."
