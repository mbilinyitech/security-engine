// Hybrid grant verification: ECDSA P-384 **and** ML-DSA-87, both required.
//
// Verification only. No signing, no key generation, no secret material.

#ifndef SOV_HYBRID_H
#define SOV_HYBRID_H

#include <linux/types.h>

/**
 * sov_hybrid_transcript_len() - bytes needed for the signed transcript
 * @domain_len: domain-separation tag length
 * @msg_len:    message length
 *
 * The transcript layout is
 *   "SOVEREIGN/v1/hybrid-sign" || u32_be(len) || domain || u32_be(len) || msg
 * and must match sovereign-crypto's `transcript()` byte for byte.
 */
size_t sov_hybrid_transcript_len(size_t domain_len, size_t msg_len);

/**
 * sov_hybrid_verify() - verify ECDSA P-384 **and** ML-DSA-87 over one transcript
 * @ecdsa_pub:     SEC1 uncompressed P-384 key, 97 bytes
 * @mldsa_vk:      ML-DSA-87 verifying key, 2592 bytes
 * @domain:        domain-separation tag
 * @domain_len:    its length
 * @msg:           message both signatures cover
 * @msg_len:       its length
 * @ecdsa_sig:     raw r||s, 96 bytes
 * @ecdsa_sig_len: must be 96
 * @mldsa_sig:     ML-DSA-87 signature, 4627 bytes
 * @mldsa_sig_len: must be 4627
 * @scratch:       caller-provided buffer of at least sov_hybrid_transcript_len()
 * @scratch_len:   its length
 *
 * Returns 0 only when both signatures verify over the same transcript. Any other result means
 * the grant is not from the holder of both keys. Callers must treat every non-zero return as
 * a refusal; there is no partial acceptance.
 *
 * Context: process context. May sleep (allocates with GFP_KERNEL).
 */
int sov_hybrid_verify(const u8 *ecdsa_pub, const u8 *mldsa_vk, const u8 *domain,
		      size_t domain_len, const u8 *msg, size_t msg_len, const u8 *ecdsa_sig,
		      size_t ecdsa_sig_len, const u8 *mldsa_sig, size_t mldsa_sig_len, u8 *scratch,
		      size_t scratch_len);

#endif
