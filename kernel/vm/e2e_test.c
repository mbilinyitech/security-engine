/* End-to-end: the blob below came out of `sovereign-bridge kernel-grant`, which derived it
 * from a grant that passed the hybrid ECDSA + ML-DSA-87 verification. The kernel has never
 * seen any of that; it only sees 109 bytes and must decide. */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include "e2e.h"

int main(void) {
    int fd = open("/dev/sovereign_gate", O_RDWR);
    if (fd < 0) { printf("  FAIL open: %d\n", errno); return 1; }

    ssize_t w = write(fd, e2e_blob, 109);
    printf("  write(109 from sovereign-bridge) = %zd\n", w);

    char buf[8];
    errno = 0;
    ssize_t r = read(fd, buf, sizeof buf);
    printf("  read() = %zd errno=%d\n", r, errno);

    if (w == 109 && r == 0) {
        printf("  ok   kernel accepted a grant minted by sovereign-bridge\n");
        printf("RESULT: end-to-end passed\n");
        return 0;
    }
    printf("  FAIL kernel refused the bridge's grant\n");
    printf("RESULT: end-to-end FAILED\n");
    return 1;
}
