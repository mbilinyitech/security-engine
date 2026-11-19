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
insmod /sovereign_gate.ko root_key_hex=@ROOT_KEY@
echo "insmod_exit=$?"
ls -l /dev/sovereign_gate

echo "=== gate behaviour ==="
/bin/vmt
echo "vmt_exit=$?"

echo "=== end-to-end: grant minted by sovereign-bridge ==="
/bin/e2e_test
echo "e2e_exit=$?"

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
insmod /sov_mldsa.ko
echo "mldsa_insmod_exit=$?"
ls /sys/kernel/sov_mldsa/
echo 1 > /sys/kernel/sov_mldsa/selftest
echo "mldsa_selftest_exit=$?"
rmmod sov_mldsa
echo "mldsa_rmmod_exit=$?"

echo "=== dmesg ==="
dmesg | grep -iE "sovereign|sov_iommu|sov_mldsa"

poweroff -f
