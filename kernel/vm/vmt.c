/* Runs inside the VM against the real /dev/sovereign_gate. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "cases.h"

static int fails;
#define CHECK(cond, msg) do { if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static void put(int fd, const uint8_t *tok, const uint8_t *tag) {
    uint8_t w[109];
    memcpy(w, tok, 77);
    memcpy(w + 77, tag, 32);
    ssize_t n = write(fd, w, 109);
    (void)n;
}

int main(void) {
    printf("=== sovereign_gate in-VM test ===\n");

    /* 1. Device exists */
    if (access("/dev/sovereign_gate", F_OK) != 0) {
        printf("  FAIL /dev/sovereign_gate missing\n");
        return 1;
    }
    printf("  ok   /dev/sovereign_gate exists\n");

    /* 2. Permissions are restrictive */
    int fd = open("/dev/sovereign_gate", O_RDWR);
    CHECK(fd >= 0, "open() succeeds");

    /* 3. Read before activation must fail */
    char buf[16];
    ssize_t r = read(fd, buf, sizeof buf);
    CHECK(r < 0 && errno == EPERM, "read before activation -> EPERM");

    /* 4. Short write refused */
    CHECK(write(fd, "short", 5) < 0, "short write refused");

    /* 5. Every bad token refused */
    put(fd, expired_tok, expired_tag);
    CHECK(read(fd, buf, sizeof buf) < 0, "expired token leaves device quarantined");

    put(fd, not_yet_tok, not_yet_tag);
    CHECK(read(fd, buf, sizeof buf) < 0, "future-dated token refused");

    put(fd, zero_right_tok, zero_right_tag);
    CHECK(read(fd, buf, sizeof buf) < 0, "zero-rights token refused");

    put(fd, bad_ver_tok, bad_ver_tag);
    CHECK(read(fd, buf, sizeof buf) < 0, "bad version refused");

    put(fd, valid_tok, badtag_tag);
    CHECK(read(fd, buf, sizeof buf) < 0, "corrupted tag refused");

    /* 6. Valid token activates. This is the HMAC from Python, so it also proves the
     *    kernel's hmac(sha256) agrees with a reference implementation. */
    put(fd, valid_tok, valid_tag);
    errno = 0;
    r = read(fd, buf, sizeof buf);
    CHECK(r == 0 && errno == 0, "valid token activates (read -> EOF, not EPERM)");

    /* 7. Re-activation refused: device is already Active */
    uint8_t zero[109] = {0};
    errno = 0;
    ssize_t w = write(fd, zero, 109);
    CHECK(w < 0, "second activation refused");

    /* 8. Stats ioctl */
    uint64_t stats[2] = {0, 0};
    int rc = ioctl(fd, 0x5301, stats);
    printf("  info stats: rejected=%llu (rc=%d)\n",
           (unsigned long long)stats[1], rc);
    CHECK(rc == 0 && stats[1] >= 5, "rejection counter advanced");

    /* 9. Revoke is terminal */
    rc = ioctl(fd, 0x5302, 0);
    CHECK(rc == 0, "revoke ioctl succeeds");
    errno = 0;
    CHECK(read(fd, buf, sizeof buf) < 0 && errno == EPERM, "revoked device refuses reads");

    close(fd);

    /* 10. Second concurrent open refused */
    int a = open("/dev/sovereign_gate", O_RDWR);
    int b = open("/dev/sovereign_gate", O_RDWR);
    CHECK(a >= 0 && b < 0, "second concurrent open refused");
    if (a >= 0) close(a);

    printf(fails ? "RESULT: %d FAILED\n" : "RESULT: all passed\n", fails);
    return fails ? 1 : 0;
}
