// Verification half of the pq-crystals Dilithium reference, extracted so that the kernel
// module links no signing code, no key generation and no RNG.
//
// The code in `body` below is the upstream reference verbatim (public domain / Apache-2.0,
// see kernel/mldsa/LICENSE). Splitting it out rather than writing my own was a deliberate
// choice: a hand-written post-quantum verifier that has never been attacked is worth less than
// a widely reviewed one, and this way the review surface is the diff, not the algorithm.
//
// What changed from upstream, and why:
//   * The `pre` prefix (domain separation for the context string) is passed in by the caller,
//     so the 257-byte stack buffer in crypto_sign_verify never exists in kernel context.
//   * No other change. Do not "clean up" the reference code below; matching upstream is the
//     point.

#include <stdint.h>
#include <stddef.h>

/* Kernel-only includes. The same file is compiled in userspace for the cross-check against the
 * Rust signer, where the workspace lives on the heap via malloc instead. */
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/string.h>
#define ws_alloc(sz) kzalloc((sz), GFP_KERNEL)
#define ws_free(p, sz)                       \
  do {                                       \
    memzero_explicit((p), (sz));             \
    kfree(p);                                \
  } while (0)
#else
#include <stdlib.h>
#include <string.h>
#define ws_alloc(sz) calloc(1, (sz))
#define ws_free(p, sz) free(p)
#endif

#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "symmetric.h"
#include "fips202.h"

/* All of the verifier's large objects, in one allocation. Keeping them together means a
 * single kfree on every exit path, which is the kind of thing that is easy to get wrong when
 * the buffers are freed individually. */
struct verify_workspace {
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
};

int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk)
{
  unsigned int i;
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  keccak_state state;
  struct verify_workspace *ws;
  int ret = -1;

  if(siglen != CRYPTO_BYTES)
    return -1;

  /* The kernel stack is 16 KiB and these objects total roughly 60 KiB, so they cannot be
   * locals. Allocation failure is reported as -2, distinct from -1 ("bad signature"), so a
   * caller under memory pressure does not log a valid signature as an attack. */
  ws = ws_alloc(sizeof(*ws));
  if(!ws)
    return -2;

  unpack_pk(rho, &ws->t1, pk);
  if(unpack_sig(c, &ws->z, &ws->h, sig))
    goto out;
  if(polyvecl_chknorm(&ws->z, GAMMA1 - BETA))
    goto out;

  /* Compute CRH(H(rho, t1), pre, msg) */
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&ws->cp, c);
  polyvec_matrix_expand(ws->mat, rho);

  polyvecl_ntt(&ws->z);
  polyvec_matrix_pointwise_montgomery(&ws->w1, ws->mat, &ws->z);

  poly_ntt(&ws->cp);
  polyveck_shiftl(&ws->t1);
  polyveck_ntt(&ws->t1);
  polyveck_pointwise_poly_montgomery(&ws->t1, &ws->cp, &ws->t1);

  polyveck_sub(&ws->w1, &ws->w1, &ws->t1);
  polyveck_reduce(&ws->w1);
  polyveck_invntt_tomont(&ws->w1);

  /* Reconstruct w1 */
  polyveck_caddq(&ws->w1);
  polyveck_use_hint(&ws->w1, &ws->w1, &ws->h);
  polyveck_pack_w1(ws->buf, &ws->w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, ws->buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  ret = 0;
  for(i = 0; i < CTILDEBYTES; ++i) {
    if(c[i] != c2[i]) {
      ret = -1;
      break;
    }
  }

out:
  /* The workspace held no secrets, but it did hold attacker-influenced data; clearing it
   * costs microseconds and removes any question of stale bytes leaking between calls. */
  ws_free(ws, sizeof(*ws));
  return ret;
}
