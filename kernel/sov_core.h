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
static inline int sov_validate(const uint8_t *wire, size_t len, uint64_t now,
			       const uint8_t *root_key, const uint8_t *tag)
{
	struct sov_token t;
	uint8_t expected[SOV_TAG_LEN];
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

	rc = sov_hmac_sha256(root_key, 32, wire, SOV_TOKEN_LEN, expected);
	if (rc != 0) {
		sov_memzero(expected, sizeof(expected));
		sov_memzero(&t, sizeof(t));
		return SOV_E_TAG;
	}

	rc = sov_ct_equal(expected, tag, SOV_TAG_LEN) ? SOV_OK : SOV_E_TAG;
	sov_memzero(expected, sizeof(expected));
	sov_memzero(&t, sizeof(t));
	return rc;
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
