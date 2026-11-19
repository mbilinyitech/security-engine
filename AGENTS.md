# AGENTS.md

Repository notes for future sessions.

## Build

Rust 1.88+ (verified on 1.100.0). Toolchain lives at `$HOME/.cargo/bin`; add it to `PATH` first.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo build            # all crates
cargo test             # 129 tests, all pass
cargo clippy --all-targets   # must stay clean
cargo fmt --all
```

`clippy` and `rustfmt` are not installed by default: `rustup component add clippy rustfmt`.

## Pinned dependency versions

`p384` 0.14 (needs features `ecdsa, arithmetic, sha384, pkcs8, ecdh, std`), `ml-kem` 0.3,
`ml-dsa` 0.1, `hkdf` 0.13, `sha2` 0.11, `chacha20poly1305` 0.11 (features `alloc, zeroize` —
note it has **no** `std` feature), `zeroize` 1.9, `hex` 0.4, `getrandom` 0.4.

API gotchas worth remembering:

* `ml_kem::EncapsulationKey::to_bytes` needs `ml_kem::KeyExport` in scope.
* `p384` `PublicKey::to_sec1_point` needs `elliptic_curve::sec1::ToSec1Point`; ECDH needs the
  `ecdh` feature or `SecretKey::diffie_hellman` does not exist.
* `XNonce::from_slice` is deprecated; use `&XNonce::from(array)`.
* `SecretKey::random` / `EphemeralSecret::random` are deprecated in favour of the `Generate`
  trait (`try_generate_from_rng`).
* `Rights` is a newtype with private field: you cannot write `impl Rights` outside
  `sovereign-ipc` (orphan rule). Test constants go in the test module instead.

## Architecture invariants — do not weaken these

1. **Hybrid verification is AND-composed.** Both the ECDSA and ML-DSA halves must verify. Tests
   `both_halves_are_required` (crypto) and `tampered_grant_fails_verification` (bridge) guard this.
2. **Rights only ever shrink:** `requested ∩ certificate ∩ PLUGIN_RIGHTS_CEILING`. `ADMIN` is
   deliberately outside the ceiling. Guarded by `admin_is_never_granted_to_a_plugin`.
3. **Capability tokens are bound to the handshake nonce.** A token from session A must be inert
   in session B. Guarded by `stolen_token_cannot_be_replayed_into_a_new_session`.
4. **The AEAD associated data binds capability id + counter + epoch** (not the nonce — that is
   the AEAD's own input). Changing `SealedFrame::associated_data` is a wire-format break.
5. **Parse before allocate.** `sovereign-ipc` validates the declared length against
   `MAX_PAYLOAD` before any `vec![0; n]`. Keep it that way.
6. **Replay window advances only after authentication succeeds**, so garbage cannot burn counters.

## Where the code is

* `crates/sovereign-crypto/src/sign.rs` — hybrid signatures, domain-separated length-prefixed
  transcript (prevents signature splicing).
* `crates/sovereign-crypto/src/kem.rs` — hybrid KEM, both public keys bound into HKDF info
  (prevents key-mix attacks).
* `crates/sovereign-crypto/src/replay.rs` — 2048-bit sliding window; bit 0 is `high - 1`.
* `crates/sovereign-ipc/src/lib.rs` — all wire types. `Rights::from_bits` rejects reserved bits.
* `crates/sovereign-bridge/src/handshake.rs` — state machine, `PLUGIN_RIGHTS_CEILING`,
  `Handshake::from_challenge` (stateless host reconstruction from the nonce alone).
* `crates/sovereign-bridge/src/session.rs` — `Session::seal` checks the capability before doing
  any crypto; `open` advances the replay window only after the tag verifies.
* `crates/sovereign-bridge/src/main.rs` — CLI. `host` self-checks the grant it mints, including a
  round-trip seal/open probe, before printing it.

## Mutation testing results (verified, do not regress)

Deliberately broke each security-critical path and recorded which tests went red. Re-run these
if you change the relevant code; a mutation that no test catches means the test is decorative.

| Mutation | Caught by |
| --- | --- |
| `HybridVerifyingKey::verify` ignores the ML-DSA half (OR instead of AND) | `both_halves_are_required` |
| `PLUGIN_RIGHTS_CEILING` intersect removed | `admin_is_never_granted_to_a_plugin`, `a_device_that_asks_only_for_admin_gets_nothing` |
| Nonce check removed from `MockKernel::accept_grant` | `stolen_token_cannot_be_replayed_into_a_new_session`, `bridge_crash_does_not_leave_a_usable_session` |
| `capability_id` dropped from AEAD associated data | `sovereign_ipc::sealed_frame_roundtrip` |
| Both `Session::open` capability check AND AAD binding removed | `frames_cannot_be_moved_between_devices` |
| Domain tag dropped from the signed transcript | `sign_and_verify_roundtrip`, `wrong_domain_fails` |

Note the two-layer result: removing *either* the explicit capability check or the AAD binding
alone leaves `frames_cannot_be_moved_between_devices` green, because the other layer still
rejects the frame. That is intentional defence in depth, not a weak test — but do not "simplify"
by deleting one layer thinking the test will catch you.

## What exists now, and what still does not

`crates/sovereign-tunnel` is a real UDP transport: per-peer replay windows, bucket padding, and
chaff. It has been exercised over real loopback sockets, not only in memory.

`kernel/` contains three out-of-tree modules. `insmod` returns EPERM in this container (no
`CAP_SYS_MODULE`), so they are exercised in a QEMU VM instead: `./kernel/vm/run.sh` builds them,
boots a stock Debian kernel with `intel-iommu` and a QEMU `edu` PCI device, loads all three, and
asserts 12 behaviours. The gate module is covered by 16 in-kernel checks (device registration,
`file_operations`, `copy_from_user`, the state machine, `hmac(sha256)`); `sov_iommu.ko` by a real
DMA test; `sov_mldsa.ko` by 8 ML-DSA-87 checks. Concurrency under load and real hardware remain
untested.

The decision logic lives in `kernel/sov_core.h`, free of kernel APIs, so the same header compiles
into `test_sov_core.c` — 14 tests via `make -C kernel test`, no kernel needed.

**A real bug this found.** `sov_validate` used to MAC `(const uint8_t *)t`, the parsed struct.
Struct padding and native endianness made that tag agree with nothing outside the module. The C
tests passed because they hashed the struct too: both sides were consistently wrong. It only
surfaced when the module ran against a tag produced by CPython. `sov_validate` now takes wire
bytes, and `test_sov_core.c` has an HMAC vector from CPython plus SHA-256 known-answer tests. If
you change the signature of `sov_validate`, keep the wire-bytes contract.

Still absent, and must not be described as present:

* **The gate does not call the ML-DSA verifier.** `sov_mldsa.ko` verifies ML-DSA-87 correctly
  (proven in-kernel), but `sovereign_gate.ko` still accepts grants on `hmac(sha256)` alone.
  Wiring them needs a grant format carrying the public key and both signature halves.
* **No ECDSA P-384 verifier in kernel space**, so the hybrid check cannot be completed there.
* **IOMMU containment covers one device, chosen by BDF.** `sov_iommu.ko` genuinely contains it
  (real DMA lands when mapped, dropped when not), but it does not mediate PCIe enumeration and
  the gate does not route through it.
* Remote hardware attestation (TPM 2.0, TDX, SEV). No such devices exist in this container.
* Onion routing, LoRa mesh, QUIC mimicry. The tunnel is a plain-UDP transport with replay
  protection and padding; padding hides length, not timing.

## Kernel ML-DSA-87 notes (learned the hard way)

* **The kernel has no `<stdint.h>` or `<stddef.h>`.** Probed it: `#include <stdint.h>` fails to
  compile in a module. `kernel/mldsa/shim/` maps `uint32_t` etc. onto `linux/types.h`, and the
  Kbuild `-I` flags put it first.
* **The reference verifier needs ~60 KiB of stack.** Kernel stack is 16 KiB. `verify_only.c`
  allocates one `kzalloc` workspace and frees it on every exit path, including the error paths.
  Do not move those buffers back to locals.
* **Extract, do not rewrite.** `verify_only.c` is the upstream `crypto_sign_verify_internal`
  verbatim, minus the 257-byte context buffer (the caller builds the FIPS 204 prefix instead).
  The point of vendoring is that the algorithm is not mine to get wrong.
* **Symbols are namespaced** by `DILITHIUM_NAMESPACE` in `config.h`; include `mldsa/sign.h` so
  `crypto_sign_verify_internal` resolves to `pqcrystals_dilithium5_ref_verify_internal`.
* **Signing and keygen are not compiled.** `randombytes.c` aborts if called, which it never is
  on the verify path. Keep it that way — the module must not link an RNG.
* **Test vectors are generated, not typed.** `sov_mldsa_test_vectors.h` comes from
  `cargo test -p sovereign-crypto --test pq_kat -- --nocapture`. Regenerate, do not hand-edit.
* **A bit-flip test must target the code path it claims to test.** My first "corrupted
  signature" test flipped a bit in `z`; when I mutated the `c_tilde` comparison to one byte, the
  test still passed. The tests now flip a bit at `sig[32]` (inside `c_tilde`, past byte 0) and in
  the hint. Mutation check that actually fails: deleting the whole `c_tilde` comparison makes
  two checks red and the VM verdict exit non-zero.

## Cross-language invariants

The kernel hard-codes the capability-token layout, so two tests exist purely to stop silent
drift:

* `kernel/test_sov_core.c` asserts `SOV_TOKEN_LEN == 77` and every field offset.
* `crates/sovereign-ipc/tests/kernel_layout.rs` asserts the same offsets against the real
  `CapabilityToken::encode`, and pins that `Rights::SENSOR_READ` shares no bit with `ADMIN`.

Verified by mutation: reordering `rights` after `expires_at` in the encoder turns
`every_field_sits_at_the_offset_the_kernel_reads` red.

## Tunnel mutation results (verified)

| Mutation | Caught by |
| --- | --- |
| Pad-underflow check removed in `Datagram::decode` | `a_corrupt_pad_length_cannot_underflow_the_parser`, `a_truncated_datagram_is_refused_without_panicking` |
| Per-peer replay `accept` removed in `UdpTransport::recv_frame` | `a_replayed_datagram_is_refused_over_a_real_socket`, `the_replay_window_is_per_peer` |
| Sender allow-list removed | `a_peer_outside_the_allow_list_is_ignored` |
| `fill_random` dropped from `chaff_datagram` | `chaff_bodies_differ_between_packets` |

The chaff mutation initially passed: the first version of the tests only checked the packet
*size*, so predictable cover traffic went unnoticed. `chaff_bodies_differ_between_packets` was
added to close that. Worth remembering — a test that only checks a length proves very little.

## Build and test

```sh
cargo test --all              # 129 Rust tests
cargo clippy --all-targets -- -D warnings
make -C kernel test           # 14 C tests, runs here
make -C kernel                # builds sovereign_gate.ko, sov_iommu.ko, sov_mldsa.ko
./kernel/vm/run.sh            # boots QEMU, loads all three, asserts 12 behaviours
```

Three implementations must agree on the grant tag: Rust (`sovereign-crypto::grant_tag`), C
(`sov_core.h`), and CPython (`kernel/vm/gen.py`). They are pinned to one vector:
`cb3ee767...`. If you change token layout, all three break together, which is the point.

`sovereign-bridge kernel-grant <grant> <root-key-hex>` produces the 109-byte blob
`/dev/sovereign_gate` accepts. It refuses to emit anything whose token is not exactly 77 bytes.

`cargo clippy` runs with `indexing_slicing` denied in the tunnel crate, so slicing in a parser is
a compile error rather than a code-review question. Fix it with `split_at_checked` / `get`, not
with an `allow`.

## Commit style

Conventional-ish subject lines, imperative mood. Repo started with no commits.
