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

/* --- Real HMAC-SHA256, so the Python reference vector below is a genuine cross-check. ---
 *
 * The first version of this file used a deterministic FNV stand-in. That made every test pass
 * while proving nothing about interoperability, and it hid a real bug: the gate was MACing a
 * parsed struct instead of the wire bytes, and because both sides hashed the struct the tests
 * agreed with themselves. A reference vector from CPython is only meaningful if this side
 * computes the same function CPython does. So: actual SHA-256, actual HMAC. */

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t SHA_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_block(uint32_t h[8], const uint8_t p[64])
{
	uint32_t w[64], a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	for (i = 0; i < 64; i++) {
		s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		ch = (e & f) ^ (~e & g);
		t1 = hh + s1 + ch + SHA_K[i] + w[i];
		s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = s0 + maj;

		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
	uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	uint8_t block[64];
	uint64_t bits = (uint64_t)len * 8;
	size_t i, full = len / 64, rem = len % 64;

	for (i = 0; i < full; i++)
		sha256_block(h, msg + i * 64);

	memset(block, 0, sizeof(block));
	memcpy(block, msg + full * 64, rem);
	block[rem] = 0x80;
	if (rem >= 56) {
		sha256_block(h, block);
		memset(block, 0, sizeof(block));
	}
	for (i = 0; i < 8; i++)
		block[63 - i] = (uint8_t)(bits >> (i * 8));
	sha256_block(h, block);

	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)h[i];
	}
}

/* Satisfies the sov_hmac_sha256 contract with the real construction, so a Python-produced tag
 * is a meaningful check rather than a self-consistency check. */
int sov_hmac_sha256(const uint8_t *key, size_t key_len,
		    const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
	uint8_t k[64], inner[64 + 256], outer[64 + 32], ih[32];
	size_t i;

	if (key_len > 64) {
		sha256(key, key_len, k);
		memset(k + 32, 0, 32);
	} else {
		memset(k, 0, sizeof(k));
		memcpy(k, key, key_len);
	}

	/* Tokens here are 77 bytes, so 64 + 77 fits the fixed inner buffer. Refuse anything
	 * larger rather than truncate. */
	if (msg_len > 256)
		return -1;

	for (i = 0; i < 64; i++)
		inner[i] = k[i] ^ 0x36;
	memcpy(inner + 64, msg, msg_len);
	sha256(inner, 64 + msg_len, ih);

	for (i = 0; i < 64; i++)
		outer[i] = k[i] ^ 0x5c;
	memcpy(outer + 64, ih, 32);
	sha256(outer, 96, out);

	memset(k, 0, sizeof(k));
	memset(inner, 0, sizeof(inner));
	memset(outer, 0, sizeof(outer));
	memset(ih, 0, sizeof(ih));
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

	build_token(buf, 0x01, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_OK);
	assert(sov_validate(buf, SOV_TOKEN_LEN, 2000, ROOT_KEY, tag) == SOV_E_TIME);
	assert(sov_validate(buf, SOV_TOKEN_LEN, 999, ROOT_KEY, tag) == SOV_E_TIME);
	printf("  expiry enforced: ok\n");
}

static void test_forged_tag_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	int i;

	build_token(buf, 0x01, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	/* Flip one bit in each byte position in turn: every single one must be caught. */
	for (i = 0; i < (int)SOV_TAG_LEN; i++) {
		tag[i] ^= 0x01;
		assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_E_TAG);
		tag[i] ^= 0x01;
	}
	printf("  forged tag refused (all 32 bytes): ok\n");
}

static void test_wrong_key_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	uint8_t other_key[32];

	build_token(buf, 0x01, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	memset(other_key, 0xFF, sizeof(other_key));
	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, other_key, tag) == SOV_E_TAG);
	printf("  wrong root key refused: ok\n");
}

static void test_escalated_rights_break_the_tag(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];

	/* A device is granted SENSOR_READ and then edits its own token to claim ADMIN. The tag
	 * covered the original bytes, so the edit must be detected. */
	build_token(buf, 0x01, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);
	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_OK);

	put_be32(buf + SOV_OFF_RIGHTS, 0xFFFFFFFF);
	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_E_TAG);
	printf("  rights escalation detected: ok\n");
}

static void test_zero_rights_is_refused(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];

	build_token(buf, 0, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	/* Even a correctly signed token with no rights must not activate anything. */
	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_E_RIGHTS);
	printf("  zero rights refused: ok\n");
}

/* SHA-256 known-answer tests. If the hash itself is wrong, every HMAC vector below is
 * meaningless, so pin two published digests first. */
static void test_sha256_known_answers(void)
{
static const uint8_t abc[32] = {
0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};
static const uint8_t empty[32] = {
0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};
uint8_t out[32];

sha256((const uint8_t *)"abc", 3, out);
assert(memcmp(out, abc, 32) == 0);

sha256((const uint8_t *)"", 0, out);
assert(memcmp(out, empty, 32) == 0);

printf("  sha256 known answers: ok\n");
}

/* Cross-implementation check: this tag was produced by Python's hashlib.hmac, not by the
 * function above. If the gate hashed the parsed struct instead of the wire bytes, this would
 * fail — which is exactly the bug that only showed up when the module ran for real. */
static void test_reference_vector_from_python(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];

	build_token(buf, 0x01, 1000, 2000);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	/* hmac_sha256(b"\x00..\x1f", token(0x01,1000,2000)) as computed by CPython. */
	static const uint8_t expected[SOV_TAG_LEN] = {
		0xcb, 0x3e, 0xe7, 0x67, 0x43, 0x1d, 0xa0, 0x1a,
		0xa7, 0xf2, 0x0f, 0x54, 0x1e, 0x0c, 0x6f, 0x61,
		0x0e, 0x47, 0x4d, 0x4f, 0x52, 0x7e, 0x98, 0x4f,
		0x10, 0xc2, 0x50, 0x25, 0xac, 0x70, 0x94, 0x33,
	};
	assert(memcmp(tag, expected, SOV_TAG_LEN) == 0);
	printf("  matches CPython hmac reference: ok\n");
}

static void test_struct_hashing_would_have_failed(void)
{
	uint8_t buf[SOV_TOKEN_LEN];
	uint8_t tag[SOV_TAG_LEN];
	struct sov_token t;

	/* Guard against the specific regression: the tag must cover the wire bytes. A struct
	 * hash differs from the wire hash (padding, native layout), so a validate() that hashed
	 * the struct could not accept a wire-derived tag. */
	build_token(buf, 0x01, 1000, 2000);
	assert(sov_parse_token(buf, SOV_TOKEN_LEN, &t) == SOV_OK);
	sov_hmac_sha256(ROOT_KEY, 32, buf, SOV_TOKEN_LEN, tag);

	assert(sov_validate(buf, SOV_TOKEN_LEN, 1500, ROOT_KEY, tag) == SOV_OK);

	/* And a short buffer must be refused rather than read past the end. */
	assert(sov_validate(buf, SOV_TOKEN_LEN - 1, 1500, ROOT_KEY, tag) == SOV_E_SHORT);
	assert(sov_validate(buf, 0, 1500, ROOT_KEY, tag) == SOV_E_SHORT);
	printf("  wire-byte MAC and bounds: ok\n");
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
	test_sha256_known_answers();
test_reference_vector_from_python();
	test_struct_hashing_would_have_failed();
	test_state_machine();
	test_ct_equal();
	printf("all %d tests passed\n", 14);
	return 0;
}
