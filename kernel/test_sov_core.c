/* User-space tests for the plug-in gate core logic.
 *
 * This is the part of the kernel work that can actually be exercised on this machine. It does
 * not test the module's device registration, file_operations, or locking — those need a loaded
 * module. It does test every decision the gate makes about a token.
 *
 * Build and run:  make -C kernel test
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sov_core.h"

/* --- A stand-in for the kernel's hmac(sha256), so this builds without OpenSSL. ---
 *
 * This is NOT HMAC-SHA256. It is a deterministic 32-byte function of key and message, which is
 * all these tests need: they check the gate's control flow, not the hash. The real
 * implementation is supplied by the kernel's crypto API in the module build. Stated plainly
 * because a reader could otherwise assume the tag is cryptographically meaningful here. */
int sov_hmac_sha256(const uint8_t *key, size_t key_len,
		    const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < key_len; i++)
		h = (h ^ key[i]) * 16777619u;
	for (i = 0; i < msg_len; i++)
		h = (h ^ msg[i]) * 16777619u;

	for (i = 0; i < 32; i++) {
		h = (h ^ (uint32_t)i) * 16777619u;
		out[i] = (uint8_t)(h >> 24);
	}
	return 0;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

/* Build a token the way sovereign-ipc would. */
static void build_token(uint8_t buf[SOV_TOKEN_LEN], uint32_t rights, uint64_t issued,
			uint64_t expires)
{
	memset(buf, 0, SOV_TOKEN_LEN);
	buf[SOV_OFF_VERSION] = 1;
	memset(buf + SOV_OFF_DEVICE_ID, 0xAB, 16);
	put_be32(buf + SOV_OFF_RIGHTS, rights);
	put_be64(buf + SOV_OFF_ISSUED_AT, issued);
	put_be64(buf + SOV_OFF_EXPIRES_AT, expires);
	put_be64(buf + SOV_OFF_COUNTER_BASE, 1);
	memset(buf + SOV_OFF_NONCE, 0xCD, 32);
}

static const uint8_t ROOT_KEY[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static void test_layout_constants(void)
{
	/* These offsets are the contract with sovereign-ipc. If the Rust encoder changes, this
	 * file must change with it. */
	assert(SOV_TOKEN_LEN == 77);
	assert(SOV_OFF_VERSION == 0);
	assert(SOV_OFF_DEVICE_ID == 1);
	assert(SOV_OFF_RIGHTS == 17);
	assert(SOV_OFF_ISSUED_AT == 21);
	assert(SOV_OFF_EXPIRES_AT == 29);
	assert(SOV_OFF_COUNTER_BASE == 37);
	assert(SOV_OFF_NONCE == 45);
	assert(SOV_OFF_NONCE + 32 == SOV_TOKEN_LEN);
	printf("  layout constants: ok\n");
}

static void test_parse_roundtrip(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	struct sov_token t;

	build_token(buf, 0x0F, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	assert(t.version == 1);
	assert(t.rights == 0x0F);
	assert(t.issued_at == 1000);
	assert(t.expires_at == 2000);
	assert(t.counter_base == 1);
	assert(t.device_id[0] == 0xAB);
	assert(t.handshake_nonce[31] == 0xCD);
	printf("  parse roundtrip: ok\n");
}

static void test_wrong_length_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	struct sov_token t;

	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN - 1, &t) == SOV_E_SHORT);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN + 1, &t) == SOV_E_SHORT);
	assert(sov_parse_token(buf, 0, &t) == SOV_E_SHORT);
	assert(sov_parse_token(NULL, SOV_TOKEN_LEN, &t) == SOV_E_SHORT);
	printf("  wrong length refused: ok\n");
}

static void test_bad_version_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	struct sov_token t;

	build_token(buf, 0x01, 1000, 2000);
	buf[SOV_OFF_VERSION] = 2;
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_E_VERSION);
	printf("  bad version refused: ok\n");
}

static void test_expired_token_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	struct sov_token t;

	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, (const uint8_t *)&t, SOV_TOKEN_LEN, tag);

	assert(sov_validate(&t, 1500, ROOT_KEY, tag) == SOV_OK);
	assert(sov_validate(&t, 2000, ROOT_KEY, tag) == SOV_E_TIME);
	assert(sov_validate(&t, 999, ROOT_KEY, tag) == SOV_E_TIME);
	printf("  expiry enforced: ok\n");
}

static void test_forged_tag_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	struct sov_token t;
	int i;

	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, (const uint8_t *)&t, SOV_TOKEN_LEN, tag);

	/* Flip one bit in each byte position in turn: every single one must be caught. */
	for (i = 0; i < (int)SOV_TAG_LEN; i++) {
		tag[i] ^= 0x01;
		assert(sov_validate(&t, 1500, ROOT_KEY, tag) == SOV_E_TAG);
		tag[i] ^= 0x01;
	}
	printf("  forged tag refused (all 32 bytes): ok\n");
}

static void test_wrong_key_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	uint8_t other_key[32];
	struct sov_token t;

	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, (const uint8_t *)&t, SOV_TOKEN_LEN, tag);

	memset(other_key, 0xFF, sizeof(other_key));
	assert(sov_validate(&t, 1500, other_key, tag) == SOV_E_TAG);
	printf("  wrong root key refused: ok\n");
}

static void test_escalated_rights_break_the_tag(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	struct sov_token t;

	/* A device asks for SENSOR_READ and is granted it. It then edits its own token to claim
	 * ADMIN. The tag was computed over the original, so the edit must be detected. */
	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, (const uint8_t *)&t, SOV_TOKEN_LEN, tag);
	assert(sov_validate(&t, 1500, ROOT_KEY, tag) == SOV_OK);

	t.rights = 0xFFFFFFFF;
	assert(sov_validate(&t, 1500, ROOT_KEY, tag) == SOV_E_TAG);
	printf("  rights escalation detected: ok\n");
}

static void test_zero_rights_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	struct sov_token t;

	build_token(buf, 0, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, (const uint8_t *)&t, SOV_TOKEN_LEN, tag);

	/* Even a correctly signed token with no rights must not activate anything. */
	assert(sov_validate(&t, 1500, ROOT_KEY, tag) == SOV_E_RIGHTS);
	printf("  zero rights refused: ok\n");
}

static void test_state_machine(void)
{
	struct sov_file f = { .state = SOV_QUARANTINED, 0, 0 };

	/* Quarantined + bad token: stays quarantined, records the rejection. */
	assert(sov_activate(&f, SOV_E_TAG) == SOV_E_TAG);
	assert(f.state == SOV_QUARANTINED);
	assert(f.frames_rejected == 1);

	/* Quarantined + good token: active. */
	assert(sov_activate(&f, SOV_OK) == SOV_OK);
	assert(f.state == SOV_ACTIVE);

	/* Active + another token: refused. Re-activation must not be a way in. */
	assert(sov_activate(&f, SOV_OK) == SOV_E_STATE);
	assert(f.state == SOV_ACTIVE);

	/* Revoked is terminal. */
	f.state = SOV_REVOKED;
	assert(sov_activate(&f, SOV_OK) == SOV_E_STATE);
	assert(f.state == SOV_REVOKED);

	assert(sov_activate(NULL, SOV_OK) == SOV_E_STATE);
	printf("  state machine: ok\n");
}

static void test_ct_equal(void)
{
	uint8_t a[32], b[32];
	int i;

	memset(a, 0x5A, sizeof(a));
	memcpy(b, a, sizeof(b));
	assert(sov_ct_equal(a, b, 32) == 1);

	/* Every byte position must break equality, including the last, which is where a
	 * short-circuiting compare would be weakest. */
	for (i = 0; i < 32; i++) {
		b[i] ^= 0x80;
		assert(sov_ct_equal(a, b, 32) == 0);
		b[i] ^= 0x80;
	}
	printf("  constant-time equality: ok\n");
}

int main(void)
{
	printf("sov_core tests\n");
	test_layout_constants();
	test_parse_roundtrip();
	test_wrong_length_is_refused();
	test_bad_version_is_refused();
	test_expired_token_is_refused();
	test_forged_tag_is_refused();
	test_wrong_key_is_refused();
	test_escalated_rights_break_the_tag();
	test_zero_rights_is_refused();
	test_state_machine();
	test_ct_equal();
	printf("all %d tests passed\n", 11);
	return 0;
}
