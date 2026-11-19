// ECDSA P-384 verification, in kernel space.
//
// ## Why this exists
//
// sov_mldsa.ko verifies the post-quantum half of a capability grant. That alone is not the
// hybrid guarantee: the design requires ECDSA P-384 **and** ML-DSA-87, so that an attacker
// must break both a classical curve and a lattice scheme. With only the ML-DSA half checked in
// the kernel, the classical half was decorative. This file closes that.
//
// ## What it uses
//
// The kernel's own akcipher "ecdsa-nist-p384" implementation (CONFIG_CRYPTO_ECDSA), not a
// vendored curve implementation. The kernel crypto API is maintained upstream and is already
// present on any kernel built with that option, so there is no third copy of P-384 to audit.
//
// ## The ABI, established empirically
//
// The headers do not say what set_pub_key() accepts or how the verify buffer is laid out. These
// were established by probing a running kernel with a throwaway module, since deleted:
//
//   * set_pub_key() takes SEC1 uncompressed: 0x04 || X || Y, 97 bytes for P-384.
//     It rejects DER SubjectPublicKeyInfo and it rejects raw X||Y.
//   * verify() takes DER signature || digest, with src_len = the DER signature length and
//     dst_len = the digest length. Raw r||s is rejected with -EBADMSG.
//   * The digest is not specified by the akcipher API; the caller hashes. We use SHA-384,
//     matching what sovereign-crypto signs.
//
// Those three facts are the whole reason this file is short. Do not "simplify" the key or
// signature encoding without re-establishing them against a real kernel: guessing here produces
// a verifier that rejects everything, which the selftest catches, or accepts nothing valid,
// which it also catches. Do not change it blind.

#include "sov_ecdsa.h"

#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Largest DER-encoded P-384 signature: SEQUENCE + two INTEGERs, each up to 49 bytes of
 * content (48 bytes plus a sign byte), so 2 + 2*(2+49) = 104. The buffer is fixed rather
 * than sized at run time because the encoder below is bounded. */
#define SOV_ECDSA_DER_MAX 104

/* Encode r||s (96 bytes) as DER SEQUENCE{INTEGER r, INTEGER s}.
 *
 * The kernel wants DER, and Rust produces r||s. Doing this conversion here keeps the wire
 * format in sovereign-crypto unchanged and puts the quirky part next to the code that needs
 * it. Returns the DER length, or a negative errno. */
static int sov_ecdsa_rs_to_der(const u8 *rs, size_t rs_len, u8 *der, size_t der_cap)
{
	const u8 *r = rs;
	const u8 *s = rs + rs_len / 2;
	size_t half = rs_len / 2;
	size_t rlen, slen;
	size_t off = 0;
	u8 *body;

	if (rs_len != 96 || der_cap < SOV_ECDSA_DER_MAX)
		return -EINVAL;

	/* DER INTEGER: strip leading zeroes, then add one back if the top bit is set, because
	 * DER integers are signed and a P-384 coordinate is unsigned. */
	while (half > 1 && *r == 0) {
		r++;
		half--;
	}
	rlen = half;
	while (half > 1 && *s == 0) {
		s++;
		half--;
	}
	slen = half;

	/* 0x30, length, then two 0x02-prefixed integers. */
	der[off++] = 0x30;
	body = &der[off];
	off++; /* length byte, filled in below */

	der[off++] = 0x02;
	der[off++] = (u8)(rlen + ((r[0] & 0x80) ? 1 : 0));
	if (r[0] & 0x80)
		der[off++] = 0x00;
	memcpy(der + off, r, rlen);
	off += rlen;

	der[off++] = 0x02;
	der[off++] = (u8)(slen + ((s[0] & 0x80) ? 1 : 0));
	if (s[0] & 0x80)
		der[off++] = 0x00;
	memcpy(der + off, s, slen);
	off += slen;

	*body = (u8)(off - 2);
	return (int)off;
}

int sov_ecdsa384_verify(const u8 *sec1_pub, const u8 *msg, size_t msg_len, const u8 *sig_rs,
			size_t sig_len)
{
	struct crypto_akcipher *tfm = NULL;
	struct akcipher_request *req = NULL;
	struct crypto_shash *shash = NULL;
	struct shash_desc *desc = NULL;
	struct scatterlist src_sg;
	u8 *der = NULL;
	u8 *src = NULL;
	u8 digest[SOV_ECDSA384_DIGEST_LEN];
	int der_len;
	int rc;

	if (!sec1_pub || !msg || !sig_rs)
		return -EINVAL;
	if (sig_len != SOV_ECDSA384_SIG_LEN)
		return -EINVAL;

	der = kmalloc(SOV_ECDSA_DER_MAX, GFP_KERNEL);
	if (!der)
		return -ENOMEM;

	der_len = sov_ecdsa_rs_to_der(sig_rs, sig_len, der, SOV_ECDSA_DER_MAX);
	if (der_len < 0) {
		rc = der_len;
		goto out;
	}

	shash = crypto_alloc_shash("sha384", 0, 0);
	if (IS_ERR(shash)) {
		rc = PTR_ERR(shash);
		shash = NULL;
		goto out;
	}

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(shash), GFP_KERNEL);
	if (!desc) {
		rc = -ENOMEM;
		goto out;
	}
	desc->tfm = shash;

	rc = crypto_shash_digest(desc, msg, msg_len, digest);
	if (rc)
		goto out;

	tfm = crypto_alloc_akcipher("ecdsa-nist-p384", 0, 0);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}

	rc = crypto_akcipher_set_pub_key(tfm, sec1_pub, SOV_ECDSA384_PUB_LEN);
	if (rc)
		goto out;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}

	/* verify() reads signature || digest from one buffer, with src_len covering only the
	 * signature and dst_len the digest. Verified by probe; see the header comment. */
	src = kmalloc((size_t)der_len + sizeof(digest), GFP_KERNEL);
	if (!src) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(src, der, der_len);
	memcpy(src + der_len, digest, sizeof(digest));

	sg_init_one(&src_sg, src, (unsigned int)(der_len + sizeof(digest)));
	akcipher_request_set_crypt(req, &src_sg, NULL, (unsigned int)der_len,
				   (unsigned int)sizeof(digest));

	rc = crypto_akcipher_verify(req);
	/* The akcipher returns -EBADMSG for a bad signature and -EINVAL for a malformed one.
	 * Both mean "not the holder of this key", so callers see one code. */
	if (rc)
		rc = -EBADMSG;

out:
	if (src) {
		memzero_explicit(src, (size_t)der_len + SOV_ECDSA384_DIGEST_LEN);
		kfree(src);
	}
	if (req)
		akcipher_request_free(req);
	if (tfm)
		crypto_free_akcipher(tfm);
	if (desc)
		kfree(desc);
	if (shash)
		crypto_free_shash(shash);
	if (der) {
		memzero_explicit(der, SOV_ECDSA_DER_MAX);
		kfree(der);
	}
	memzero_explicit(digest, sizeof(digest));
	return rc;
}

#ifdef SOV_ECDSA_SELFTEST

#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "sov_ecdsa_test_vectors.h"

static struct kobject *ecdsa_kobj;
static int ecdsa_pass;
static int ecdsa_fail;

static void check(const char *what, int ok)
{
	if (ok) {
		ecdsa_pass++;
		pr_info("sov_ecdsa:   ok   %s\n", what);
	} else {
		ecdsa_fail++;
		pr_info("sov_ecdsa:   FAIL %s\n", what);
	}
}

static void run_selftest(void)
{
	u8 bad_sig[sizeof(ecdsa_vec_sig)];
	u8 bad_pub[sizeof(ecdsa_vec_pub)];

	ecdsa_pass = 0;
	ecdsa_fail = 0;

	/* The vector was produced by sovereign-crypto's p384 signer. If this fails, the ABI
	 * described at the top of this file has changed underneath us. */
	check("valid signature accepted",
	      sov_ecdsa384_verify(ecdsa_vec_pub, ecdsa_vec_msg, sizeof(ecdsa_vec_msg),
				  ecdsa_vec_sig, sizeof(ecdsa_vec_sig)) == 0);

	/* A single flipped bit in r must not verify. Without this, a verifier that returns 0
	 * unconditionally would pass the check above. */
	memcpy(bad_sig, ecdsa_vec_sig, sizeof(bad_sig));
	bad_sig[10] ^= 0x01;
	check("tampered signature rejected",
	      sov_ecdsa384_verify(ecdsa_vec_pub, ecdsa_vec_msg, sizeof(ecdsa_vec_msg), bad_sig,
				  sizeof(bad_sig)) != 0);

	/* A different public key must not verify a signature it did not make. */
	memcpy(bad_pub, ecdsa_vec_pub, sizeof(bad_pub));
	bad_pub[1] ^= 0x01;
	check("wrong public key rejected",
	      sov_ecdsa384_verify(bad_pub, ecdsa_vec_msg, sizeof(ecdsa_vec_msg), ecdsa_vec_sig,
				  sizeof(ecdsa_vec_sig)) != 0);

	/* A changed message must not verify: proves the digest is over the caller's bytes and
	 * not, say, over nothing. */
	{
		u8 bad_msg[sizeof(ecdsa_vec_msg)];

		memcpy(bad_msg, ecdsa_vec_msg, sizeof(bad_msg));
		bad_msg[0] ^= 0x01;
		check("tampered message rejected",
		      sov_ecdsa384_verify(ecdsa_vec_pub, bad_msg, sizeof(bad_msg), ecdsa_vec_sig,
					  sizeof(ecdsa_vec_sig)) != 0);
	}

	/* Wrong-length signature: refused on the length check, not by reading past the end. */
	check("short signature refused",
	      sov_ecdsa384_verify(ecdsa_vec_pub, ecdsa_vec_msg, sizeof(ecdsa_vec_msg),
				  ecdsa_vec_sig, sizeof(ecdsa_vec_sig) - 1) == -EINVAL);

	check("NULL arguments refused",
	      sov_ecdsa384_verify(NULL, ecdsa_vec_msg, sizeof(ecdsa_vec_msg), ecdsa_vec_sig,
				  sizeof(ecdsa_vec_sig)) == -EINVAL);

	pr_info("sov_ecdsa: selftest %s (%d passed, %d failed)\n",
		ecdsa_fail ? "FAILED" : "passed", ecdsa_pass, ecdsa_fail);
	pr_info("sov_ecdsa: RESULT: %s\n",
		ecdsa_fail ? "selftest failed" : "selftest passed");
}

static ssize_t selftest_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			      size_t count)
{
	(void)kobj;
	(void)attr;
	(void)buf;
	run_selftest();
	return count;
}

static struct kobj_attribute selftest_attr = __ATTR_WO(selftest);
static struct attribute *ecdsa_attrs[] = { &selftest_attr.attr, NULL };
static struct attribute_group ecdsa_attr_group = { .attrs = ecdsa_attrs };

#endif /* SOV_ECDSA_SELFTEST */

static int __init sov_ecdsa_init(void)
{
#ifdef SOV_ECDSA_SELFTEST
	ecdsa_kobj = kobject_create_and_add("sov_ecdsa", kernel_kobj);
	if (!ecdsa_kobj)
		return -ENOMEM;
	if (sysfs_create_group(ecdsa_kobj, &ecdsa_attr_group)) {
		kobject_put(ecdsa_kobj);
		ecdsa_kobj = NULL;
		return -ENOMEM;
	}
#endif
	pr_info("sov_ecdsa: loaded\n");
	return 0;
}

static void __exit sov_ecdsa_exit(void)
{
#ifdef SOV_ECDSA_SELFTEST
	if (ecdsa_kobj) {
		sysfs_remove_group(ecdsa_kobj, &ecdsa_attr_group);
		kobject_put(ecdsa_kobj);
		ecdsa_kobj = NULL;
	}
#endif
	pr_info("sov_ecdsa: unloaded\n");
}

module_init(sov_ecdsa_init);
module_exit(sov_ecdsa_exit);

/* Consumed by sov_hybrid.ko. GPL-only: this is kernel-internal plumbing, not a stable ABI
 * offered to out-of-tree callers. */
EXPORT_SYMBOL_GPL(sov_ecdsa384_verify);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sovereign ECDSA P-384 verification for capability grants");
