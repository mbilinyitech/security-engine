// ECDSA P-384 verification, in kernel space.
//
// Verification only. No signing and no key generation: a verifier needs only public data, so
// the kernel never holds a private key and a kernel compromise cannot mint grants.

#ifndef SOV_ECDSA_H
#define SOV_ECDSA_H

#include <linux/types.h>

/* FIPS 186-5 P-384 sizes. */
#define SOV_ECDSA384_PUB_LEN 97   /* SEC1 uncompressed: 0x04 || X || Y */
#define SOV_ECDSA384_SIG_LEN 96   /* r || s, 48 bytes each */
#define SOV_ECDSA384_DIGEST_LEN 48 /* SHA-384 */

/**
 * sov_ecdsa384_verify() - verify an ECDSA P-384 signature over @msg
 * @sec1_pub: public key, SOV_ECDSA384_PUB_LEN bytes, SEC1 uncompressed
 * @msg:      message that was signed (hashed with SHA-384 internally)
 * @msg_len:  message length
 * @sig_rs:   signature, SOV_ECDSA384_SIG_LEN bytes, raw r||s as Rust emits it
 * @sig_len:  must be SOV_ECDSA384_SIG_LEN
 *
 * Returns 0 when the signature is valid, -EBADMSG when it is not, -EINVAL for malformed
 * arguments, or another negative errno on allocation failure.
 *
 * Context: process context. Allocates with GFP_KERNEL and may sleep.
 */
int sov_ecdsa384_verify(const u8 *sec1_pub, const u8 *msg, size_t msg_len, const u8 *sig_rs,
			size_t sig_len);

#endif
