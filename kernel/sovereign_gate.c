// Sovereign plug-in gate: kernel module implementing layer 2 of the design.
//
// STATUS: builds against 6.8 and 6.12 headers, and runs in a QEMU VM. This container has no
// CAP_SYS_MODULE, so `kernel/vm/run.sh` boots a real kernel and loads it there. See
// kernel/README.md for exactly what that does and does not prove.
//
// What is genuinely implemented and tested:
//
//   * Token parsing, expiry, rights and tag checks, and the Quarantined -> Active state machine
//     live in sov_core.h, also compiled into kernel/test_sov_core.c and run without a kernel by
//     `make -C kernel test`.
//   * A Rust test in sovereign-ipc asserts the token layout matches the real encoder.
//   * Device registration, file_operations, copy_from_user, and the kernel's hmac(sha256) are
//     exercised in the VM by 16 checks.
//
// What is NOT implemented here (sov_iommu.ko covers DMA containment separately):
//
//   * No IOMMU isolation in this module. It gates a character device; it does not mediate PCIe
//     enumeration, so a device already bound to a driver bypasses it. Real DMA containment is
//     in sov_iommu.c.
//   * No ECDSA or ML-DSA verification in this file. sov_hmac_sha256 is wired to the kernel's
//     hmac(sha256). sov_mldsa_wrap.c verifies ML-DSA-87 in kernel space, but this gate does not
//     call it: that needs a grant format carrying the public key and both signature halves,
//     which has not been designed.
//   * No TPM, TDX or SEV attestation. No such hardware here, and no code pretending otherwise.

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <crypto/hash.h>

#include "sov_core.h"

#define SOV_IOCTL_STATS 0x5301
#define SOV_IOCTL_REVOKE 0x5302

static dev_t sov_devno;
static struct cdev sov_cdev;
static struct class *sov_class;
static struct device *sov_device;

/* One owner at a time. A second open is refused rather than queued, so a rogue process cannot
 * hold the gate open and starve the legitimate driver. */
static atomic_t sov_open_count = ATOMIC_INIT(0);

static u8 sov_root_key[32];
static bool sov_key_set;

/* Root key from a module parameter. This is the honest weak point: a parameter is visible in
 * /sys/module and may reach the kernel log. Production would take the key from a sealed source
 * such as TPM NV or a blob verified against a compiled-in key. */
static char *root_key_hex;
module_param(root_key_hex, charp, 0400);
MODULE_PARM_DESC(root_key_hex, "Hex-encoded 32-byte root key (test only; visible in sysfs)");

static u8 sov_hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return (u8)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (u8)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (u8)(c - 'A' + 10);
	return 0xFF;
}

static int sov_parse_key(const char *hex)
{
	size_t len, i;

	if (!hex)
		return -EINVAL;
	len = strlen(hex);
	if (len != 64)
		return -EINVAL;

	for (i = 0; i < 32; i++) {
		u8 hi = sov_hex_val(hex[i * 2]);
		u8 lo = sov_hex_val(hex[i * 2 + 1]);

		if (hi == 0xFF || lo == 0xFF)
			return -EINVAL;
		sov_root_key[i] = (u8)((hi << 4) | lo);
	}
	return 0;
}

/* HMAC-SHA256 via the kernel crypto API, satisfying the contract declared in sov_core.h.
 * This is not the hybrid signature the bridge produces; see the header comment. */
int sov_hmac_sha256(const u8 *key, size_t key_len,
		    const u8 *msg, size_t msg_len, u8 out[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	if (key_len != 32)
		return -EINVAL;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;

	ret = crypto_shash_setkey(tfm, key, key_len);
	if (ret)
		goto out;
	ret = crypto_shash_init(desc);
	if (ret)
		goto out;
	ret = crypto_shash_update(desc, msg, msg_len);
	if (ret)
		goto out;
	ret = crypto_shash_final(desc, out);
out:
	kfree_sensitive(desc);
	crypto_free_shash(tfm);
	return ret;
}

static int sov_open(struct inode *inode, struct file *file)
{
	struct sov_file *sf;

	if (!sov_key_set)
		return -ENOKEY;

	if (atomic_inc_return(&sov_open_count) > 1) {
		atomic_dec(&sov_open_count);
		return -EBUSY;
	}

	sf = kzalloc(sizeof(*sf), GFP_KERNEL);
	if (!sf) {
		atomic_dec(&sov_open_count);
		return -ENOMEM;
	}
	sf->state = SOV_QUARANTINED;
	file->private_data = sf;
	return 0;
}

static int sov_release(struct inode *inode, struct file *file)
{
	struct sov_file *sf = file->private_data;

	if (sf) {
		sov_memzero(sf, sizeof(*sf));
		kfree(sf);
	}
	atomic_dec(&sov_open_count);
	return 0;
}

/* Refused until Active. This is the point of quarantine: an unverified device gets no data at
 * all, not merely limited data. */
static ssize_t sov_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct sov_file *sf = file->private_data;

	if (!sf)
		return -EINVAL;
	if (sf->state != SOV_ACTIVE) {
		sf->frames_rejected++;
		return -EPERM;
	}
	/* No device behind this yet, so there is nothing to read. Reporting EOF is honest;
	 * inventing data would be worse. */
	return 0;
}

/* Writing a 109-byte grant (77-byte token + 32-byte tag) attempts Quarantined -> Active. */
static ssize_t sov_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct sov_file *sf = file->private_data;
	u8 *wire;
	int rc;

	if (!sf)
		return -EINVAL;
	if (count != SOV_WIRE_LEN)
		return -EINVAL;

	wire = kzalloc(SOV_WIRE_LEN, GFP_KERNEL);
	if (!wire)
		return -ENOMEM;

	if (copy_from_user(wire, buf, SOV_WIRE_LEN)) {
		rc = -EFAULT;
		goto out;
	}

	/* sov_validate parses the token itself and MACs the wire bytes, so there is no parsed
	 * struct here to leak or to accidentally hash. */
	rc = sov_validate(wire, SOV_TOKEN_LEN, ktime_get_real_seconds(), sov_root_key,
			  wire + SOV_TOKEN_LEN);

	rc = sov_activate(sf, rc);
out:
	sov_memzero(wire, SOV_WIRE_LEN);
	kfree(wire);
	if (rc != SOV_OK)
		return rc == -EFAULT ? -EFAULT : -EPERM;
	return count;
}

static long sov_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sov_file *sf = file->private_data;
	u64 stats[2];

	if (!sf)
		return -EINVAL;

	switch (cmd) {
	case SOV_IOCTL_STATS:
		stats[0] = sf->frames_in;
		stats[1] = sf->frames_rejected;
		if (copy_to_user((void __user *)arg, stats, sizeof(stats)))
			return -EFAULT;
		return 0;
	case SOV_IOCTL_REVOKE:
		sf->state = SOV_REVOKED;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations sov_fops = {
	.owner = THIS_MODULE,
	.open = sov_open,
	.release = sov_release,
	.read = sov_read,
	.write = sov_write,
	.unlocked_ioctl = sov_ioctl,
/* no llseek: no_llseek was removed in 6.12 and llseek defaults to no_llseek there. */
};

static int __init sov_init(void)
{
	int ret;

	if (root_key_hex) {
		ret = sov_parse_key(root_key_hex);
		if (ret) {
			pr_err("sovereign_gate: root_key_hex must be 64 hex characters\n");
			return ret;
		}
		sov_key_set = true;
	} else {
		pr_warn("sovereign_gate: no root_key_hex; every grant will be refused\n");
	}

	ret = alloc_chrdev_region(&sov_devno, 0, 1, "sovereign_gate");
	if (ret)
		return ret;

	cdev_init(&sov_cdev, &sov_fops);
	sov_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sov_cdev, sov_devno, 1);
	if (ret)
		goto err_region;

	sov_class = class_create("sovereign_gate");
	if (IS_ERR(sov_class)) {
		ret = PTR_ERR(sov_class);
		goto err_cdev;
	}

	sov_device = device_create(sov_class, NULL, sov_devno, NULL, "sovereign_gate");
	if (IS_ERR(sov_device)) {
		ret = PTR_ERR(sov_device);
		goto err_class;
	}

	pr_info("sovereign_gate: loaded\n");
	return 0;

err_class:
	class_destroy(sov_class);
err_cdev:
	cdev_del(&sov_cdev);
err_region:
	unregister_chrdev_region(sov_devno, 1);
	return ret;
}

static void __exit sov_exit(void)
{
	device_destroy(sov_class, sov_devno);
	class_destroy(sov_class);
	cdev_del(&sov_cdev);
	unregister_chrdev_region(sov_devno, 1);
	sov_memzero(sov_root_key, sizeof(sov_root_key));
	pr_info("sovereign_gate: unloaded\n");
}

module_init(sov_init);
module_exit(sov_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sovereign plug-in gate: capability-checked character device");
MODULE_AUTHOR("Sovereign project");
