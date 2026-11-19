#ifndef CONFIG_H
#define CONFIG_H

/* Parameter set and symbol namespacing for the vendored reference.
 *
 * ML-DSA-87 is Dilithium mode 5 (K=8, L=7, tau=60, c_tilde=64). The mode is set from the
 * Kbuild flags so that the kernel build and the userspace cross-check cannot drift apart;
 * this file only supplies the default and the symbol prefix. */

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 5
#endif

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium2_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2_ref_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium3_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3_ref_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium5_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5_ref_##s
#else
#error "unsupported DILITHIUM_MODE"
#endif

#endif
