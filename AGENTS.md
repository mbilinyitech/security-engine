# AGENTS.md

Repository notes for future sessions.

## Build

Rust 1.88+ (verified on 1.100.0). Toolchain lives at `$HOME/.cargo/bin`; add it to `PATH` first.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo build            # all crates
cargo test             # 255 tests, all pass
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
* `slh-dsa` cannot rebuild a keypair from arbitrary raw bytes: `from_seed` is private. Use
  `SigningKey::new(&mut rng)` with `sovereign_crypto::seeded_rng::SeededRng`, which is an
  HKDF-derived RNG, so keys are deterministic and reproducible from seeds.
* `rand_core` must match `slh-dsa`'s version exactly (0.10). A mismatch produces a trait error
  that does not mention either crate by name.
* The bare-metal crate cannot live in the workspace: it builds `no_std` for
  `x86_64-unknown-none` and would break `cargo test`. `kernel-rust/` has its own `[workspace]`.
* Do **not** put `[build] target = ...` in `kernel-rust/.cargo/config.toml`. It applies to
  `cargo test` too, which then tries to build the test harness for bare metal. Pass the target
  on the command line in `build.sh` / `run.sh` instead.
* `panic = "abort"` belongs in the target rustflags, not the profile, or `cargo test` on the
  host refuses to build.
* A `no_std` binary with its own `#[panic_handler]` cannot be `cargo test`ed. Put shared logic in
  a `no_std` **library** (`kernel-rust/gate-core/`) and depend on it from the binary.
* QEMU's `-kernel` rejects an ELF64 without a PVH note. Add `.note.Xen` with
  `XEN_ELFNOTE_PHYS32_ENTRY`, and keep the linker script's `.note.Xen` section.
* QEMU's `-kernel` with a multiboot1 header present takes the multiboot path and then refuses
  the 64-bit ELF. Either provide multiboot1 *and* a 32-bit image, or drop multiboot entirely and
  use PVH. This repo uses PVH.
* `-nographic` with stdin redirected loses the guest's serial output. Use
  `-serial file:<path>` in scripts.
* `eax`/`ebx` are clobbered by the 32-bit boot stage. Save them to statics before touching
  anything, then load them into `edi`/`esi` for the System V call into Rust.

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
7. **Tri-hybrid signatures are AND-composed across all three halves** (ECDSA P-384, ML-DSA-87,
   SLH-DSA-256s). Guarded by the `tri` test module; a mutation removing the SLH verification is
   caught.
8. **Swarm gates veto; swarm corroborators must agree.** A single gate rejecting is a plain
   rejection, never a disagreement. Conflating them makes an expired token look like a
   compromised verifier, which destroys the value of the alarm.
9. **The kernel gate refuses before it advances the replay counter.** Check order is state,
   then validity window, then replay. Reversing the last two lets an attacker burn a legitimate
   token by replaying it first.
10. **Device-supplied strings are refused, not sanitised.** A model name containing a newline
    forges a log line; `sovereign-interop` rejects it rather than stripping it.
11. **Interop and bridge must grant the same rights for the same request.** Guarded by
    `the_os_agnostic_handshake_and_the_sovereign_handshake_reach_the_same_verdict`.

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

`kernel/` contains six out-of-tree modules. `insmod` returns EPERM in this container (no
`CAP_SYS_MODULE`), so they are exercised in a QEMU VM instead: `./kernel/vm/run.sh` builds them,
boots a stock Debian kernel with `intel-iommu` and a QEMU `edu` PCI device, loads every module,
and asserts 21 behaviours. The gate module is covered by 16 in-kernel checks (device
registration, `file_operations`, `copy_from_user`, the state machine, `hmac(sha256)`);
`sov_iommu.ko` by a real DMA test; `sov_mldsa.ko` by 8 ML-DSA-87 checks; `sov_ecdsa.ko` by 6
P-384 checks; `sov_hybrid.ko` by 9 AND-composition checks; and the gate itself by two end-to-end
writes, one accepted and one tampered-and-refused. Concurrency under load and real hardware
remain untested.

The decision logic lives in `kernel/sov_core.h`, free of kernel APIs, so the same header compiles
into `test_sov_core.c` — 14 tests via `make -C kernel test`, no kernel needed.

**A real bug this found.** `sov_validate` used to MAC `(const uint8_t *)t`, the parsed struct.
Struct padding and native endianness made that tag agree with nothing outside the module. The C
tests passed because they hashed the struct too: both sides were consistently wrong. It only
surfaced when the module ran against a tag produced by CPython. `sov_validate` now takes wire
bytes, and `test_sov_core.c` has an HMAC vector from CPython plus SHA-256 known-answer tests. If
you change the signature of `sov_validate`, keep the wire-bytes contract.

**Hybrid verification is now real and in the gate.** `sovereign_gate.ko` accepts a 4809-byte v2
grant (`"SOVG" | 2 | token ‖ len ‖ ECDSA sig ‖ len ‖ ML-DSA sig`) and verifies it with
`sov_hybrid_verify`, which requires **both** `sov_ecdsa384_verify` and `sov_mldsa87_verify` to
accept. It is an AND, never an OR. The 109-byte v1 hmac format is still accepted for
compatibility. It is symmetric: the module holds the same key that mints grants, so anyone who
reads that key out of the module can forge one. v2 is the path that survives a module compromise.

Two mutations were run against the integration and both were caught: making `sov_verify_v2`
return `SOV_OK` unconditionally (the tampered-grant end-to-end check fails), and skipping the
ML-DSA half inside `sov_hybrid_verify` (hybrid selftest, cross-paired halves and both end-to-end
checks fail). Keep those mutation results in mind when changing either function: if a mutation
is *not* caught, the test is not testing what its name claims.

Still absent, and must not be described as present:

* **Key provisioning is the weak point.** The two verifying keys arrive as `module_param_cb`
  parameters — out of `/sys/module` (permission 0) and parsed straight into fixed buffers, but
  still present in the `insmod` command line and the kernel log. Production should compile them
  in or read them from TPM NV. What *is* true is that the attacker cannot supply them at grant
  time; that is what stops a forged grant.
* **v1 is accepted by default.** A hybrid-only deployment should refuse the 109-byte format in
  `sov_write`; not done here so the existing v1 tests keep working.
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
make -C kernel                # builds all six modules
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

## Bare-metal kernel notes (kernel-rust/)

`kernel-rust/` is a separate, standalone crate. It builds a multiboot/PVH image for
`x86_64-unknown-none`, enters long mode from a 32-bit stage, and runs the capability gate with
no OS underneath it. `./kernel-rust/run.sh` boots it in QEMU and asserts 12 serial lines.

**What it proves:** the boot path is ours (32-bit entry, page tables built at run time, GDT,
long-mode jump) and the gate logic works with no allocator, no scheduler, and no kernel API.

**What it does not prove:** it is not an OS. There is no IDT, so any fault triple-faults and
reboots. There is no userspace, no driver model, no scheduler. Do not describe it as more.

The gate itself is `kernel-rust/gate-core/` — a `no_std` library so it gets both ordinary unit
tests (14, on the host) and the boot-time self-check that QEMU asserts (8). Two independent
paths over one source file.

Mutation verified: deleting the replay check from `main.rs` fails `run.sh` with
`FAIL missing: gate: replay refused ... ok` and `FAIL missing: gate: 8 passed, 0 failed`.

## Swarm, ledger, agent, interop notes

* `sovereign-swarm` — `Swarm::evaluate` runs gates, any of which may veto. `Swarm::corroborate`
  runs ≥2 implementations of the same question and reports `Disagreement` on a split. Fewer
  than two corroborators is `Empty`, not an accept: one implementation cannot corroborate itself.
* `sovereign-ledger` — hash-chained, checkpoints are hybrid-signed. Tamper detection assumes the
  verifier trusts a checkpoint from outside the log; an attacker who can replace both can
  present a shorter history. Say so when describing it.
* `sovereign-agent` — manifests may only name handlers registered in code. A manifest cannot
  introduce a program. Rights are checked before the first step runs.
* `sovereign-interop` — `Transport` has exactly two methods (`send`, `recv`) and a `describe`.
  Linux is a real file descriptor, tested over a real `UnixStream::pair`. Windows and macOS
  adapters encode the shape of `DeviceIoControl` / `IOConnectCallStructMethod` without FFI.
  Do not claim a single driver binary that loads on all three; that does not exist.
* `crates/sovereign-interop/tests/full_stack.rs` is the integration test: enrol → seal → tunnel
  → open → audit → swarm → agent, plus a negative path. Mutation verified: removing the rights
  ceiling intersection in `handshake.rs` makes it fail. Note the first version of the test did
  *not* catch it, because it requested only rights already inside the ceiling — if a mutation is
  not caught, check whether the test's input actually exercises the difference.

## Commit style

Conventional-ish subject lines, imperative mood. Repo started with no commits.

## Session key derivation and the epoch ratchet (verified by mutation)

`sovereign-crypto::session_key` derives the AEAD key with HKDF-SHA-384 over the KEM output plus
the device id plus the handshake nonce. `Session::from_grant` uses it; it does **not** install the
KEM output as the key directly. `Session::rotate` calls `sovereign_crypto::ratchet`, which derives
the next epoch key from the previous one, so the old key is dropped (and zeroized) rather than
retained.

Two mutations were run and both are caught:

1. `rotate` bumps `epoch` but keeps the same key (the pre-ratchet behaviour). Caught by
   `rotation_with_different_mix_in_diverges`: with the old key retained, the two sides still
   interoperate, so `open` returns `Ok` where the test demands `Decrypt`.
2. `session_key` stops mixing in `handshake_nonce`. Caught by
   `same_shared_secret_in_different_sessions_yields_incompatible_keys`.

Note on expected errors in these tests: when device id and epoch both match but the keys differ,
the failure surfaces as `CryptoError::Decrypt` (the AEAD tag), not `CryptoError::Verification`
(the header checks). That distinction is deliberate — it is what proves the *keys* diverged
rather than the labels. Do not "fix" these tests to expect `Verification`.

Limitation to keep in mind: rotation is caller-driven. Nothing schedules it, so a session that
never rotates never gets forward secrecy. If you add a scheduler, the mix-in must come from a
fresh key exchange, not from a counter.

## Automatic ratchet, rekey, and the epoch window (verified by mutation)

Three distinct operations, and the difference between them is the whole point. Do not merge them.

| Method | Derives from | Gives | Does not give |
|---|---|---|---|
| `Session::rotate(mix_in)` | previous key + mix + epoch | forward secrecy | anything against a holder of the current key |
| `Session::ratchet_epoch()` (private) | previous key + `epoch_mix(epoch)` | same, with no caller input | same |
| `Session::rekey(shared)` | previous key + **fresh KEM secret** + epoch | post-compromise security | anything without a real exchange |

`with_auto_ratchet(n)` sets `ratchet_after`; `seal` counts frames and calls `ratchet_epoch()` once
the threshold is hit, *after* building the frame so the frame carries the epoch it was sealed
under. `open` accepts three cases: same epoch, exactly one epoch behind (`prev_key`), or ahead by
at most `MAX_EPOCH_SKIP` — walking the chain on a local copy first and committing only after the
AEAD tag verifies.

**The commit-after-authenticate rule is load-bearing.** Committing the epoch advance before
`aead_open` returns lets any unauthenticated packet with a large epoch number destroy the keys
needed for genuine in-flight frames. Mutation-verified: moving the `mem::replace` above the
`aead_open` call is caught by `a_forged_future_epoch_does_not_advance_the_receiver`.

Four mutations were run against this code, all caught:

1. Commit the epoch advance before authentication — caught by
   `a_forged_future_epoch_does_not_advance_the_receiver`.
2. Make `with_auto_ratchet` never fire — caught by three tests, including
   `a_peer_that_never_ratchets_still_opens_after_auto_ratchet`.
3. Degrade `rekey` to `ratchet` **using the same mix value** — caught by
   `a_peer_with_only_the_old_key_cannot_follow_a_rekey`. (The cruder version, passing
   `[0u8; 32]` as the mix, is only caught by the divergence test and is a weaker mutation; use the
   semantic one.)
4. Stop retaining `prev_key` — caught by `a_frame_from_one_epoch_back_still_opens` and
   `rotation_keeps_one_epoch_of_history_and_no_more`.

Expected-error note: when device id and epoch match but keys differ, the failure is
`CryptoError::Decrypt`; when the epoch is out of range or too far ahead, it is
`CryptoError::Verification`. Both are deliberate.

The one-epoch history is a stated trade, not an oversight: it costs one extra epoch of exposure to
an attacker who reads *receiver* memory, and it buys immunity to reordering. Do not "improve" it to
zero without also accepting that reordered frames are dropped.
