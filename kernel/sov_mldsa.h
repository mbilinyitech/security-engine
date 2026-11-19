// ML-DSA-87 verification, in kernel space.
//
// ## Why this exists
//
// A capability grant is signed by `sovereign-bridge` with ECDSA P-384 *and* ML-DSA-87. Until
// now the kernel could only check an HMAC tag, which means whoever held the root key could
// mint a grant — and the whole point of the hybrid signature is that no single key can. This
// module closes that gap: the kernel verifies the ML-DSA-87 half itself.
//
// ## Scope
//
// Verification only. No signing, no key generation, no secret material. That is deliberate: a
// verifier needs only public data, so the kernel never holds a private key and a kernel
// compromise does not let an attacker mint grants.
//
// ## Provenance
//
// The algorithm is the pq-crystals reference implementation (public domain / Apache-2.0),
// vendored under kernel/mldsa/ and pinned to ML-DSA-87 parameters. Writing a post-quantum
// verifier from scratch would have produced something unreviewed and probably wrong.

#ifndef SOV_MLDSA_H
#define SOV_MLDSA_H

#include <linux/types.h>

/* FIPS 204 ML-DSA-87 sizes. */
#define SOV_MLDSA87_VK_LEN 2592
#define SOV_MLDSA87_SIG_LEN 4627

/* FIPS 204 allows context strings up to 255 bytes. */
#define SOV_MLDSA87_CTX_MAX 255

/**
 * sov_mldsa87_verify() - verify an ML-DSA-87 signature
 * @vk:      public key, SOV_MLDSA87_VK_LEN bytes
 * @msg:     message
 * @msg_len: message length
 * @sig:     signature, SOV_MLDSA87_SIG_LEN bytes
 * @ctx:     context string, may be NULL only when @ctx_len is 0
 * @ctx_len: context length, at most SOV_MLDSA87_CTX_MAX
 *
 * Returns 0 when the signature is valid, -EBADMSG when it is not, -EINVAL for malformed
 * arguments. Callers that log every non-zero return as an attack will misreport malformed
 * frames, so the distinction is preserved rather than flattened.
 *
 * Context: process context. The implementation uses a large static working buffer and takes
 * a mutex, so it is not safe to call from atomic context and calls serialise.
 */
int sov_mldsa87_verify(const u8 *vk, const u8 *msg, size_t msg_len, const u8 *sig, const u8 *ctx,
       size_t ctx_len);

#endif
