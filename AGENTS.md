# AGENTS.md

Repository notes for future sessions.

## Build

Rust 1.88+ (verified on 1.100.0). Toolchain lives at `$HOME/.cargo/bin`; add it to `PATH` first.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo build            # all three crates
cargo test             # 89 tests, all pass
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

## Not implemented (do not claim otherwise)

Kernel module, IOMMU isolation, DMA zeroization, remote hardware attestation (TPM/TDX/SEV), and
the stealth network tunnel. `SealedFrame` is the interface the tunnel will consume. See the
"Scope and honest limitations" section of README.md.

## Commit style

Conventional-ish subject lines, imperative mood. Repo started with no commits.
