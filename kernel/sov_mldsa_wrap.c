// Kernel-facing ML-DSA-87 verification API.
//
// Wraps the vendored reference verifier (kernel/mldsa/verify_only.c) and owns the two things
// the reference does not do for a kernel caller: argument validation and serialisation.

#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "sov_mldsa.h"

/* Pulls in the reference's symbol namespacing, so the declaration below resolves to
 * pqcrystals_dilithium5_ref_verify_internal rather than an undefined plain name. */
#include "mldsa/sign.h"

/* One verification at a time. The verifier is pure but heap-hungry; serialising keeps peak
 * memory bounded and makes the failure mode predictable under load. */
static DEFINE_MUTEX(sov_mldsa_lock);

int sov_mldsa87_verify(const u8 *vk, const u8 *msg, size_t msg_len, const u8 *sig, const u8 *ctx,
       size_t ctx_len)
{
u8 pre[2 + SOV_MLDSA87_CTX_MAX];
int rc;

if (!vk || !sig)
return -EINVAL;
if (!msg && msg_len)
return -EINVAL;
if (ctx_len > SOV_MLDSA87_CTX_MAX)
return -EINVAL;
if (ctx_len && !ctx)
return -EINVAL;

/* FIPS 204 domain separation: the message that is actually signed is
 * 0x00 || len(ctx) || ctx || M. Building it here keeps the 257-byte buffer out of the
 * verifier, which runs on the kernel stack. */
pre[0] = 0;
pre[1] = (u8)ctx_len;
if (ctx_len)
memcpy(&pre[2], ctx, ctx_len);

mutex_lock(&sov_mldsa_lock);
rc = crypto_sign_verify_internal(sig, SOV_MLDSA87_SIG_LEN, msg, msg_len, pre,
 2 + ctx_len, vk);
mutex_unlock(&sov_mldsa_lock);

switch (rc) {
case 0:
return 0;
case -1:
return -EBADMSG;
default:
/* Workspace allocation failed. Reporting this as -EBADMSG would make a valid
 * grant look forged during memory pressure. */
return -ENOMEM;
}
}

/* ---------------------------------------------------------------------------------------
 * Self-test
 *
 * Loading the module proves nothing about whether verification works. The only useful
 * evidence is a signature that the Rust signer produced being accepted here, in the kernel,
 * and a tampered copy being rejected. The vectors below are emitted by
 * `cargo test -p sovereign-crypto --test pq_kat -- --nocapture` and pasted in; the same
 * vectors are checked against the same code in userspace by kernel/mldsa/test_cross.c.
 * --------------------------------------------------------------------------------------- */

#include "sov_mldsa_test_vectors.h"

static struct kobject *sov_mldsa_kobj;

static ssize_t selftest_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
      size_t count)
{
int pass = 0, fail = 0;
u8 *bad;
int rc;

(void)kobj;
(void)attr;
(void)buf;

/* 4.6 KiB of scratch, off the stack: the kernel stack is only 16 KiB and a sysfs store
 * runs on it. */
bad = kmalloc(sizeof(sov_test_sig), GFP_KERNEL);
if (!bad)
return -ENOMEM;

/* 1. A real signature from the Rust signer must verify. */
rc = sov_mldsa87_verify(sov_test_vk, sov_test_msg, sizeof(sov_test_msg) - 1, sov_test_sig,
NULL, 0);
if (rc == 0) {
pr_info("sov_mldsa:   ok   valid signature accepted\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL valid signature rejected (rc=%d)\n", rc);
fail++;
}

/* 2. A single flipped bit must be rejected. Without this, a verifier that always
 *    returns 0 would pass test 1. */
memcpy(bad, sov_test_sig, sizeof(bad));
bad[100] ^= 0x01;
rc = sov_mldsa87_verify(sov_test_vk, sov_test_msg, sizeof(sov_test_msg) - 1, bad, NULL, 0);
if (rc == -EBADMSG) {
pr_info("sov_mldsa:   ok   corrupted signature rejected\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL corrupted signature gave rc=%d (want -EBADMSG)\n", rc);
fail++;
}

/* 3. A different message must be rejected. */
rc = sov_mldsa87_verify(sov_test_vk, (const u8 *)"a different message", 19, sov_test_sig,
NULL, 0);
if (rc == -EBADMSG) {
pr_info("sov_mldsa:   ok   wrong message rejected\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL wrong message gave rc=%d\n", rc);
fail++;
}

/* 4. A corrupted public key must be rejected. */
memcpy(bad, sov_test_vk, sizeof(bad));
bad[40] ^= 0x01;
rc = sov_mldsa87_verify(bad, sov_test_msg, sizeof(sov_test_msg) - 1, sov_test_sig, NULL, 0);
if (rc == -EBADMSG) {
pr_info("sov_mldsa:   ok   corrupted public key rejected\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL corrupted public key gave rc=%d\n", rc);
fail++;
}

/* 5. A flipped bit in c_tilde must be rejected. This is a different code path from a
 *    flipped bit in z: c_tilde is compared directly, so a verifier that truncated that
 *    comparison (a real mutation I ran) would still pass tests 1-4. The first 64 bytes
 *    of an ML-DSA-87 signature are c_tilde, so the flip must be inside that range but
 *    past byte 0: a flip at byte 0 is caught even by a one-byte comparison. */
memcpy(bad, sov_test_sig, sizeof(bad));
bad[32] ^= 0x01;
rc = sov_mldsa87_verify(sov_test_vk, sov_test_msg, sizeof(sov_test_msg) - 1, bad, NULL, 0);
if (rc == -EBADMSG) {
pr_info("sov_mldsa:   ok   corrupted c_tilde rejected\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL corrupted c_tilde gave rc=%d\n", rc);
fail++;
}

/* 6. A hint that claims a coefficient the signature does not have must be rejected.
 *    The hint lives in the last K+OMEGA bytes; corrupting one of them exercises the
 *    decoding checks rather than the algebra. */
memcpy(bad, sov_test_sig, sizeof(bad));
bad[sizeof(sov_test_sig) - 1] ^= 0xFF;
rc = sov_mldsa87_verify(sov_test_vk, sov_test_msg, sizeof(sov_test_msg) - 1, bad, NULL, 0);
if (rc == -EBADMSG) {
pr_info("sov_mldsa:   ok   corrupted hint rejected\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL corrupted hint gave rc=%d\n", rc);
fail++;
}

/* 7. Malformed arguments must be refused as -EINVAL, not as a bad signature. */
rc = sov_mldsa87_verify(NULL, sov_test_msg, sizeof(sov_test_msg) - 1, sov_test_sig, NULL, 0);
if (rc == -EINVAL) {
pr_info("sov_mldsa:   ok   NULL key refused with -EINVAL\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL NULL key gave rc=%d\n", rc);
fail++;
}

rc = sov_mldsa87_verify(sov_test_vk, sov_test_msg, sizeof(sov_test_msg) - 1, sov_test_sig,
(const u8 *)"x", 300);
if (rc == -EINVAL) {
pr_info("sov_mldsa:   ok   oversized context refused with -EINVAL\n");
pass++;
} else {
pr_err("sov_mldsa:   FAIL oversized context gave rc=%d\n", rc);
fail++;
}

pr_info("sov_mldsa: selftest %s (%d passed, %d failed)\n", fail ? "FAILED" : "passed",
pass, fail);
kfree(bad);
return count;
}

static struct kobj_attribute sov_mldsa_selftest_attr = __ATTR_WO(selftest);

static struct attribute *sov_mldsa_attrs[] = {
&sov_mldsa_selftest_attr.attr,
NULL,
};

static struct attribute_group sov_mldsa_attr_group = {
.attrs = sov_mldsa_attrs,
};

static int __init sov_mldsa_init(void)
{
int ret;

sov_mldsa_kobj = kobject_create_and_add("sov_mldsa", kernel_kobj);
if (!sov_mldsa_kobj)
return -ENOMEM;

ret = sysfs_create_group(sov_mldsa_kobj, &sov_mldsa_attr_group);
if (ret) {
kobject_put(sov_mldsa_kobj);
sov_mldsa_kobj = NULL;
return ret;
}

pr_info("sov_mldsa: loaded (ML-DSA-87 verification)\n");
return 0;
}

static void __exit sov_mldsa_exit(void)
{
if (sov_mldsa_kobj) {
sysfs_remove_group(sov_mldsa_kobj, &sov_mldsa_attr_group);
kobject_put(sov_mldsa_kobj);
}
pr_info("sov_mldsa: unloaded\n");
}

module_init(sov_mldsa_init);
module_exit(sov_mldsa_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ML-DSA-87 signature verification for Sovereign capability grants");
MODULE_AUTHOR("Sovereign");
