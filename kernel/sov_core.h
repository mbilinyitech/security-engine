/* Shared plug-in gate logic, compiled both into the kernel module and into a user-space test.
 *
 * The split exists so the interesting part — parsing and validating a capability token — can be
 * exercised by a test on this machine, where the module itself cannot be loaded. The kernel glue
 * (device registration, file_operations) is in sovereign_gate.c and is NOT covered by that test.
 *
 * The token layout here MUST match sovereign_ipc::CapabilityToken::encode exactly:
 *
 *   version(1) | device_id(16) | rights(4, BE) | issued_at(8, BE)
 *              | expires_at(8, BE) | counter_base(8, BE) | handshake_nonce(32)
 *
 *   = 77 bytes
 *
 * A Rust test asserts this constant against the Rust encoder, so the two cannot drift apart
 * silently.
 */

#ifndef SOV_CORE_H
#define SOV_CORE_H

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#define sov_memzero(p, n) memzero_explicit((p), (n))
/* The kernel has u8/u32/u64 but no uint8_t, so alias them rather than dragging in stdint. */
typedef u8 uint8_t;
typedef u32 uint32_t;
typedef u64 uint64_t;
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define sov_memzero(p, n) explicit_bzero((p), (n))
#endif

#define SOV_TOKEN_LEN 77u
#define SOV_TAG_LEN 32u
#define SOV_WIRE_LEN (SOV_TOKEN_LEN + SOV_TAG_LEN)

/* v2 grant: hybrid ECDSA P-384 + ML-DSA-87 over the token, verified in kernel space.
 * Layout: "SOVG" | version=2 | token(77) | u16_be(len) | ecdsa | u16_be(len) | mldsa.
 * The verifying keys are NOT in the blob: an attacker would otherwise supply their own. */
#define SOV_V2_MAGIC0 'S'
#define SOV_V2_MAGIC1 'O'
#define SOV_V2_MAGIC2 'V'
#define SOV_V2_MAGIC3 'G'
#define SOV_V2_VERSION 2u
#define SOV_V2_HDR_LEN 5u
#define SOV_V2_ECDSA_SIG_LEN 96u
#define SOV_V2_MLDSA_SIG_LEN 4627u
#define SOV_V2_LEN (SOV_V2_HDR_LEN + SOV_TOKEN_LEN + 2u + SOV_V2_ECDSA_SIG_LEN + 2u + \
                    SOV_V2_MLDSA_SIG_LEN)

/* Offset of each field, so the parser does not hard-code magic numbers in two places. */
#define SOV_OFF_VERSION 0u
#define SOV_OFF_DEVICE_ID 1u
#define SOV_OFF_RIGHTS 17u
#define SOV_OFF_ISSUED_AT 21u
#define SOV_OFF_EXPIRES_AT 29u
#define SOV_OFF_COUNTER_BASE 37u
#define SOV_OFF_NONCE 45u

enum sov_state {
	SOV_QUARANTINED = 0,
	SOV_ACTIVE = 1,
	SOV_REVOKED = 2,
};

enum sov_result {
	SOV_OK = 0,
	SOV_E_SHORT = -1,
	SOV_E_VERSION = -2,
	SOV_E_RIGHTS = -3,
	SOV_E_TIME = -4,
	SOV_E_TAG = -5,
	SOV_E_STATE = -6,
SOV_E_FORMAT = -7,
};

struct sov_token {
	uint8_t version;
	uint8_t device_id[16];
	uint32_t rights;
	uint64_t issued_at;
	uint64_t expires_at;
	uint64_t counter_base;
	uint8_t handshake_nonce[32];
};

struct sov_file {
	enum sov_state state;
	uint64_t frames_in;
	uint64_t frames_rejected;
};

static inline uint32_t sov_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t sov_be64(const uint8_t *p)
{
	return ((uint64_t)sov_be32(p) << 32) | (uint64_t)sov_be32(p + 4);
}

/* Parse the 77-byte token. Returns SOV_OK or a negative sov_result. */
static inline int sov_parse_token(const uint8_t *buf, size_t len, struct sov_token *out)
{
	if (!buf || !out)
		return SOV_E_SHORT;
	if (len != SOV_TOKEN_LEN)
		return SOV_E_SHORT;

	out->version = buf[SOV_OFF_VERSION];
	if (out->version != 1)
		return SOV_E_VERSION;

	memcpy(out->device_id, buf + SOV_OFF_DEVICE_ID, sizeof(out->device_id));
	out->rights = sov_be32(buf + SOV_OFF_RIGHTS);
	out->issued_at = sov_be64(buf + SOV_OFF_ISSUED_AT);
	out->expires_at = sov_be64(buf + SOV_OFF_EXPIRES_AT);
	out->counter_base = sov_be64(buf + SOV_OFF_COUNTER_BASE);
	memcpy(out->handshake_nonce, buf + SOV_OFF_NONCE, sizeof(out->handshake_nonce));
	return SOV_OK;
}

/* Constant-time equality. A short-circuiting memcmp leaks how many leading bytes matched, which
 * is enough to forge a tag one byte at a time against a chosen message. */
static inline int sov_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < n; i++)
		diff |= (uint8_t)(a[i] ^ b[i]);
	return diff == 0;
}

/* Provided by the environment: HMAC-SHA256(key, msg) -> 32 bytes. */
int sov_hmac_sha256(const uint8_t *key, size_t key_len,
		    const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* Validate a token against a clock reading and a root key.
 *
 * The MAC covers the *wire bytes*, never the parsed struct. A struct carries compiler padding
 * and native-endian fields, so hashing it yields a tag that matches nothing else in the system.
 * This was a real bug: the first version hashed `(uint8_t *)t` and its tests passed, because the
 * tests hashed the struct too. Running against a tag from an independent implementation exposed
 * it. Do not "simplify" this back to a struct hash.
 *
 * Order matters: cheap structural checks, then time, then the MAC. Verifying the MAC first would
 * let an attacker make us do HMAC work for tokens that are obviously expired or malformed. */
/* Structural and semantic checks on a token, with no authentication.
 *
 * Split out because a v2 grant is authenticated by a signature that has already been verified
 * before this runs. Re-MACing it would be meaningless: the module holds no v1 root key on that
 * path, and pretending to check a tag it cannot compute would be worse than not checking.
 * Callers on the v1 path must still go through sov_validate(), which adds the MAC. */
static inline int sov_check_token(const uint8_t *wire, size_t len, uint64_t now)
{
	struct sov_token t;
	int rc;

	rc = sov_parse_token(wire, len, &t);
	if (rc != SOV_OK)
		return rc;

	if (t.rights == 0) {
		sov_memzero(&t, sizeof(t));
		return SOV_E_RIGHTS;
	}
	if (now < t.issued_at || now >= t.expires_at) {
		sov_memzero(&t, sizeof(t));
		return SOV_E_TIME;
	}

	sov_memzero(&t, sizeof(t));
	return SOV_OK;
}

static inline int sov_validate(const uint8_t *wire, size_t len, uint64_t now,
                               const uint8_t *root_key, const uint8_t *tag)
{
	uint8_t expected[SOV_TAG_LEN];
	int rc;

	rc = sov_check_token(wire, len, now);
	if (rc != SOV_OK)
		return rc;

	rc = sov_hmac_sha256(root_key, 32, wire, SOV_TOKEN_LEN, expected);
	if (rc != 0) {
		sov_memzero(expected, sizeof(expected));
		return SOV_E_TAG;
	}

	rc = sov_ct_equal(expected, tag, SOV_TAG_LEN) ? SOV_OK : SOV_E_TAG;
	sov_memzero(expected, sizeof(expected));
	return rc;
}

/* Split a v2 grant into its token and two signature halves, checking every length.
 *
 * This does *no* cryptography: it only proves the blob is well-formed, so the caller can then
 * hand the token to the hybrid verifier without risking an out-of-bounds read. Parsing before
 * verifying, and verifying the exact bytes that were parsed, is what stops a blob from being
 * interpreted two different ways.
 *
 * On success the out-parameters point *into* `wire`; nothing is copied. Returns SOV_OK or
 * SOV_E_FORMAT. */
static inline int sov_v2_split(const uint8_t *wire, size_t len, const uint8_t **token,
                               const uint8_t **ecdsa_sig, const uint8_t **mldsa_sig)
{
        size_t off;

        if (!wire || !token || !ecdsa_sig || !mldsa_sig)
                return SOV_E_FORMAT;
        if (len != SOV_V2_LEN)
                return SOV_E_FORMAT;
        if (wire[0] != SOV_V2_MAGIC0 || wire[1] != SOV_V2_MAGIC1 ||
            wire[2] != SOV_V2_MAGIC2 || wire[3] != SOV_V2_MAGIC3)
                return SOV_E_FORMAT;
        if (wire[4] != SOV_V2_VERSION)
                return SOV_E_FORMAT;

        off = SOV_V2_HDR_LEN;
        *token = wire + off;
        off += SOV_TOKEN_LEN;

        /* Declared lengths must match the fixed sizes exactly. Accepting a shorter signature
         * would mean the kernel and the signer disagree about what was signed. */
        if (((size_t)wire[off] << 8 | wire[off + 1]) != SOV_V2_ECDSA_SIG_LEN)
                return SOV_E_FORMAT;
        off += 2;
        *ecdsa_sig = wire + off;
        off += SOV_V2_ECDSA_SIG_LEN;

        if (((size_t)wire[off] << 8 | wire[off + 1]) != SOV_V2_MLDSA_SIG_LEN)
                return SOV_E_FORMAT;
        off += 2;
        *mldsa_sig = wire + off;

        return SOV_OK;
}

/* The state machine a file descriptor follows. Only Quarantined -> Active is allowed, and only
 * with a token that validated. Everything else is refused, including re-activation of a revoked
 * descriptor, which is the mistake a naive implementation makes. */
static inline int sov_activate(struct sov_file *f, int validation_rc)
{
	if (!f)
		return SOV_E_STATE;
	if (f->state != SOV_QUARANTINED) {
		f->frames_rejected++;
		return SOV_E_STATE;
	}
	if (validation_rc != SOV_OK) {
		f->frames_rejected++;
		return validation_rc;
	}
	f->state = SOV_ACTIVE;
	return SOV_OK;
}

#endif /* SOV_CORE_H */
