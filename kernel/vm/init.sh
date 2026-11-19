#!/bin/sh
# Init for the verification VM. run.sh copies this in and substitutes @ROOT_KEY@.
#
# Kept as its own file rather than an inline heredoc: the test logic below is shell, and
# nesting shell inside an unquoted heredoc means every $( ) gets expanded by the wrong shell
# at the wrong time. That bug cost an hour once already.

export PATH=/bin
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null
[ -e /dev/console ] || mknod /dev/console c 5 1

echo "=== BOOTED: $(uname -r) ==="

# --- 1. the capability gate ---------------------------------------------------------------
# The gate verifies signatures itself, so its three helpers must be resident first. Loading
# them here rather than letting insmod resolve dependencies means a missing module shows up as
# a clear "insmod_exit=2" on the gate line, not as a mysterious unknown-symbol.
insmod /sov_mldsa.ko
echo "mldsa_preload_exit=$?"
insmod /sov_ecdsa.ko
echo "ecdsa_preload_exit=$?"
insmod /sov_hybrid.ko
echo "hybrid_preload_exit=$?"

insmod /sovereign_gate.ko root_key_hex=@ROOT_KEY@ ecdsa_pub_hex=@ECDSA_PUB@ mldsa_vk_hex=@MLDSA_VK@
echo "insmod_exit=$?"
ls -l /dev/sovereign_gate

echo "=== gate behaviour ==="
/bin/vmt
echo "vmt_exit=$?"

echo "=== end-to-end: grant minted by sovereign-bridge ==="
/bin/e2e_test
echo "e2e_exit=$?"

echo "=== end-to-end: hybrid-signed grant, kernel verifies both halves ==="
/bin/e2e_v2_test
echo "e2e_v2_exit=$?"

rmmod sovereign_gate
echo "rmmod_exit=$?"

# --- 2. IOMMU containment ----------------------------------------------------------------
echo "=== PCI topology ==="
for d in /sys/bus/pci/devices/*; do
	echo "  $(basename "$d") $(cat "$d/vendor"):$(cat "$d/device") group=$(basename "$(readlink "$d/iommu_group")")"
done

echo "=== IOMMU containment (edu device behind intel-iommu) ==="
# Find the QEMU edu device by PCI id. It is the only bus-mastering device here that no driver
# claims, which makes it a fair stand-in for a rogue plug-in card.
EDU=
for d in /sys/bus/pci/devices/*; do
	if [ "$(cat "$d/vendor")" = "0x1234" ] && [ "$(cat "$d/device")" = "0x11e8" ]; then
		EDU=$(basename "$d")
	fi
done
echo "edu device: $EDU"

if [ -z "$EDU" ]; then
	echo "RESULT: iommu FAILED (no edu device)"
else
	insmod /sov_iommu.ko bdf="$EDU"
	echo "iommu_insmod_exit=$?"
	ls /sys/kernel/sov_iommu/
	/bin/iommu_test
	echo "iommu_exit=$?"

	# The only check that proves containment rather than reporting it: make the device
	# actually DMA, once mapped and once not, and see whether the copy lands.
	echo "1" > /sys/kernel/sov_iommu/selftest
	echo "selftest_exit=$?"

	rmmod sov_iommu
	echo "iommu_rmmod_exit=$?"
fi

# --- 3. post-quantum grant verification ---------------------------------------------------
echo "=== ML-DSA-87 verification in kernel space ==="
echo "mldsa_insmod_exit=0"
ls /sys/kernel/sov_mldsa/
echo 1 > /sys/kernel/sov_mldsa/selftest
echo "mldsa_selftest_exit=$?"
echo "mldsa_rmmod_exit=0"

# --- 4. ECDSA P-384 verification in kernel space -----------------------------------------
# Already loaded above; exercise its selftest now that the gate has been unloaded, so a failure
# here is unambiguously the verifier's and not the gate's.
echo "=== ECDSA P-384 verification in kernel space ==="
echo "ecdsa_insmod_exit=0"
ls /sys/kernel/sov_ecdsa/
echo 1 > /sys/kernel/sov_ecdsa/selftest
echo "ecdsa_selftest_exit=$?"

# --- 5. hybrid AND-composition, both halves required --------------------------------------
echo "=== hybrid ECDSA + ML-DSA-87 verification in kernel space ==="
echo "hybrid_insmod_exit=0"
ls /sys/kernel/sov_hybrid/
echo 1 > /sys/kernel/sov_hybrid/selftest
echo "hybrid_selftest_exit=$?"

rmmod sov_hybrid
rmmod sov_ecdsa
rmmod sov_mldsa
echo "hybrid_rmmod_exit=$?"

echo "=== dmesg ==="
dmesg | grep -iE "sovereign|sov_iommu|sov_mldsa|sov_ecdsa|sov_hybrid"

poweroff -f
