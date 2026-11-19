/* Only needed because sign.c links against randombytes. Verification never calls it, but the
 * symbol must exist or the link fails. Fails loudly if it is ever actually used. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void randombytes(uint8_t *out, size_t outlen)
{
(void)out;
(void)outlen;
fprintf(stderr, "randombytes called during verification: this should be unreachable\n");
abort();
}
