/* End-to-end for the v2 grant: the blob came out of `sovereign-bridge kernel-grant-v2` and
 * carries the root CA's own hybrid signature. The kernel module holds only the two public keys,
 * so it can verify the grant but cannot mint one.
 *
 * Two writes are attempted on separate descriptors:
 *   1. the blob as minted  -> must be accepted;
 *   2. one flipped byte in the ML-DSA half -> must be refused.
 *
 * The second write is the point. A verifier that accepts everything passes the first test.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include "e2e_v2.h"

static int write_once(const uint8_t *blob, size_t len) {
    int fd = open("/dev/sovereign_gate", O_RDWR);
    if (fd < 0) return -1;
    ssize_t w = write(fd, blob, len);
    int saved = errno;
    close(fd);
    errno = saved;
    return (int)w;
}

int main(void) {
    int ok = 1;

    /* 1. The grant as minted. */
    int w = write_once(e2e_v2_blob, sizeof e2e_v2_blob);
    printf("  write(v2 as minted, %zu bytes) = %d\n", sizeof e2e_v2_blob, w);
    if (w == (int)sizeof e2e_v2_blob) {
        printf("  ok   kernel accepted a hybrid-signed grant from sovereign-bridge\n");
    } else {
        printf("  FAIL kernel refused a valid hybrid-signed grant\n");
        ok = 0;
    }

    /* 2. The same grant with one byte changed in the ML-DSA half. The signature covers the
     *    token, not the signature bytes, so this is a corrupted signature rather than a
     *    corrupted message: the verifier must still say no. */
    static uint8_t tampered[sizeof e2e_v2_blob];
    memcpy(tampered, e2e_v2_blob, sizeof tampered);
    size_t mldsa_off = 5 + 77 + 2 + 96 + 2;
    tampered[mldsa_off + 32] ^= 0x01;

    errno = 0;
    int w2 = write_once(tampered, sizeof tampered);
    printf("  write(v2 tampered mldsa) = %d errno=%d\n", w2, errno);
    if (w2 < 0 && (errno == EPERM || errno == EINVAL)) {
        printf("  ok   kernel refused the tampered hybrid-signed grant\n");
    } else {
        printf("  FAIL kernel accepted a tampered hybrid-signed grant\n");
        ok = 0;
    }

    if (ok) {
        printf("RESULT: end-to-end v2 passed\n");
        printf("RESULT: end-to-end v2 rejected tampered\n");
        return 0;
    }
    printf("RESULT: end-to-end v2 FAILED\n");
    return 1;
}
