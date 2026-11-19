// Hybrid grant verification: ECDSA P-384 **and** ML-DSA-87, both required.
//
// ## The property this file exists to enforce
//
// A capability grant is signed with two independent primitives. The security claim is that an
// attacker must break both. That claim is only true if the verifier rejects a grant whose
// halves come from different signers, or whose halves are individually valid but not over the
// same message. Both checks are here:
//
//   1. AND composition: both verifications must return 0. There is no code path that accepts
//      one half.
//   2. Same-transcript binding: both halves are verified over the *same* domain-separated,
//      length-prefixed transcript, built identically to sovereign-crypto's `transcript()`.
//      Without this, an attacker could pair a valid ECDSA signature over message A with a
//      valid ML-DSA signature over message B, and both would verify.
//
// ## The transcript
//
//   "SOVEREIGN/v1/hybrid-sign" || u32_be(len(domain)) || domain || u32_be(len(msg)) || msg
//
// Byte-for-byte identical to `crates/sovereign-crypto/src/sign.rs::transcript`.

#include "sov_hybrid.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "sov_ecdsa.h"
#include "sov_mldsa.h"

/* The domain tag is part of the signed transcript, so changing it is a wire-format break. */
static const char SOV_SIGN_LABEL[] = "SOVEREIGN/v1/hybrid-sign";
#define SOV_SIGN_LABEL_LEN (sizeof(SOV_SIGN_LABEL) - 1)

static void sov_put_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

/* Build the signed transcript into a caller-supplied buffer.
 *
 * Bounded and non-allocating so the caller controls the lifetime: the transcript covers the
 * grant, which is not secret, but it is large and allocating it twice would be careless.
 * Returns the length, or -ENOSPC. */
static int sov_build_transcript(const u8 *domain, size_t domain_len, const u8 *msg, size_t msg_len,
				u8 *out, size_t out_cap)
{
	size_t need = SOV_SIGN_LABEL_LEN + 4 + domain_len + 4 + msg_len;
	size_t off = 0;

	if (need > out_cap)
		return -ENOSPC;

	memcpy(out + off, SOV_SIGN_LABEL, SOV_SIGN_LABEL_LEN);
	off += SOV_SIGN_LABEL_LEN;
	sov_put_be32(out + off, (u32)domain_len);
	off += 4;
	memcpy(out + off, domain, domain_len);
	off += domain_len;
	sov_put_be32(out + off, (u32)msg_len);
	off += 4;
	memcpy(out + off, msg, msg_len);
	off += msg_len;

	return (int)off;
}

size_t sov_hybrid_transcript_len(size_t domain_len, size_t msg_len)
{
	return SOV_SIGN_LABEL_LEN + 4 + domain_len + 4 + msg_len;
}

int sov_hybrid_verify(const u8 *ecdsa_pub, const u8 *mldsa_vk, const u8 *domain,
		      size_t domain_len, const u8 *msg, size_t msg_len, const u8 *ecdsa_sig,
		      size_t ecdsa_sig_len, const u8 *mldsa_sig, size_t mldsa_sig_len, u8 *scratch,
		      size_t scratch_len)
{
	int tlen;
	int rc;

	if (!ecdsa_pub || !mldsa_vk || !domain || !msg || !ecdsa_sig || !mldsa_sig || !scratch)
		return -EINVAL;

	tlen = sov_build_transcript(domain, domain_len, msg, msg_len, scratch, scratch_len);
	if (tlen < 0)
		return tlen;

	/* Classical half first: it is cheap and rejects most forgeries without paying for a
	 * 4.6 KiB lattice verification. This is an optimisation only; both halves always run
	 * when the first passes, so it cannot weaken the AND. */
	rc = sov_ecdsa384_verify(ecdsa_pub, scratch, (size_t)tlen, ecdsa_sig, ecdsa_sig_len);
	if (rc)
		return rc;

	rc = sov_mldsa87_verify(mldsa_vk, scratch, (size_t)tlen, mldsa_sig, NULL, 0);
	if (rc)
		return rc;

	return 0;
}

#ifdef SOV_HYBRID_SELFTEST

#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "sov_hybrid_test_vectors.h"

static struct kobject *hybrid_kobj;
static int hybrid_pass;
static int hybrid_fail;

static void check(const char *what, int ok)
{
	if (ok) {
		hybrid_pass++;
		pr_info("sov_hybrid:   ok   %s\n", what);
	} else {
		hybrid_fail++;
		pr_info("sov_hybrid:   FAIL %s\n", what);
	}
}

/* Run one verification with a scratch buffer sized for the standard vector. */
static int verify_with(const u8 *ecdsa_pub, const u8 *ecdsa_sig, const u8 *mldsa_sig)
{
	size_t tlen = sov_hybrid_transcript_len(sizeof(vec_domain), sizeof(vec_msg));
	u8 *scratch = kmalloc(tlen, GFP_KERNEL);
	int rc;

	if (!scratch)
		return -ENOMEM;
	rc = sov_hybrid_verify(ecdsa_pub, vec_mldsa_vk, vec_domain, sizeof(vec_domain), vec_msg,
			       sizeof(vec_msg), ecdsa_sig, sizeof(vec_ecdsa_sig), mldsa_sig,
			       sizeof(vec_mldsa_sig), scratch, tlen);
	kfree(scratch);
	return rc;
}

static void run_selftest(void)
{
	u8 other_domain[] = "SOVEREIGN/v1/not-the-sign-domain";
	u8 null_scratch[64];
	size_t tlen;
	u8 *scratch;
	int rc;

	hybrid_pass = 0;
	hybrid_fail = 0;

	/* The positive case. If this fails, nothing else means anything. */
	check("valid hybrid signature accepted",
	      verify_with(vec_ecdsa_pub, vec_ecdsa_sig, vec_mldsa_sig) == 0);

	/* Each half, tampered alone. These are the two that prove the AND: a verifier that
	 * checks only one primitive passes the valid case and one of these. */
	check("tampered ECDSA half rejected",
	      verify_with(vec_ecdsa_pub, vec_bad_ecdsa_sig, vec_mldsa_sig) != 0);
	check("tampered ML-DSA half rejected",
	      verify_with(vec_ecdsa_pub, vec_ecdsa_sig, vec_bad_mldsa_sig) != 0);

	/* Both halves valid, but signed by a different key. Catches a verifier that checks
	 * each signature against the wrong public key, or skips the key binding entirely. */
	check("foreign ECDSA signature rejected",
	      verify_with(vec_ecdsa_pub, vec_foreign_ecdsa_sig, vec_mldsa_sig) != 0);
	check("foreign ML-DSA signature rejected",
	      verify_with(vec_ecdsa_pub, vec_ecdsa_sig, vec_foreign_mldsa_sig) != 0);

	/* Cross-pairing: a valid ECDSA half from the right signer, but the ML-DSA half from
	 * another. Both halves are genuine signatures over the same transcript; only the key
	 * binding distinguishes them. */
	check("cross-paired halves rejected",
	      verify_with(vec_ecdsa_pub, vec_ecdsa_sig, vec_foreign_mldsa_sig) != 0);

	/* Wrong public key entirely. */
	check("wrong ECDSA public key rejected",
	      verify_with(vec_foreign_ecdsa_pub, vec_ecdsa_sig, vec_mldsa_sig) != 0);

	/* Transcript binding: a signature over a different domain must not verify. The kernel
	 * rebuilds the transcript itself, so this catches a transcript that omits the domain
	 * tag or mis-orders the length prefixes. */
	tlen = sov_hybrid_transcript_len(sizeof(vec_domain), sizeof(vec_msg));
	scratch = kmalloc(tlen, GFP_KERNEL);
	rc = -1;
	if (scratch) {
		rc = sov_hybrid_verify(vec_ecdsa_pub, vec_mldsa_vk, other_domain,
				       sizeof(other_domain) - 1, vec_msg, sizeof(vec_msg),
				       vec_ecdsa_sig, sizeof(vec_ecdsa_sig), vec_mldsa_sig,
				       sizeof(vec_mldsa_sig), scratch, tlen);
		kfree(scratch);
	}
	check("signature under a different domain rejected", rc != 0);

	/* Argument validation. A NULL must not be dereferenced. */
	check("NULL arguments refused",
	      sov_hybrid_verify(NULL, vec_mldsa_vk, vec_domain, sizeof(vec_domain), vec_msg,
				sizeof(vec_msg), vec_ecdsa_sig, sizeof(vec_ecdsa_sig), vec_mldsa_sig,
				sizeof(vec_mldsa_sig), null_scratch,
				sizeof(null_scratch)) == -EINVAL);

	pr_info("sov_hybrid: selftest %s (%d passed, %d failed)\n",
		hybrid_fail ? "FAILED" : "passed", hybrid_pass, hybrid_fail);
	pr_info("sov_hybrid: RESULT: %s\n", hybrid_fail ? "selftest failed" : "selftest passed");
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
static struct attribute *hybrid_attrs[] = { &selftest_attr.attr, NULL };
static struct attribute_group hybrid_attr_group = { .attrs = hybrid_attrs };

#endif /* SOV_HYBRID_SELFTEST */

static int __init sov_hybrid_init(void)
{
	int rc;

#ifdef SOV_HYBRID_SELFTEST
	hybrid_kobj = kobject_create_and_add("sov_hybrid", kernel_kobj);
	if (!hybrid_kobj)
		return -ENOMEM;
	rc = sysfs_create_group(hybrid_kobj, &hybrid_attr_group);
	if (rc) {
		kobject_put(hybrid_kobj);
		hybrid_kobj = NULL;
		return rc;
	}
#endif
	pr_info("sov_hybrid: loaded\n");
	return 0;
}

static void __exit sov_hybrid_exit(void)
{
#ifdef SOV_HYBRID_SELFTEST
	if (hybrid_kobj) {
		sysfs_remove_group(hybrid_kobj, &hybrid_attr_group);
		kobject_put(hybrid_kobj);
		hybrid_kobj = NULL;
	}
#endif
	pr_info("sov_hybrid: unloaded\n");
}

module_init(sov_hybrid_init);
module_exit(sov_hybrid_exit);

/* Consumed by sovereign_gate.ko. GPL-only, same reasoning as sov_ecdsa.c. */
EXPORT_SYMBOL_GPL(sov_hybrid_verify);
EXPORT_SYMBOL_GPL(sov_hybrid_transcript_len);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sovereign hybrid ECDSA P-384 + ML-DSA-87 grant verification");
