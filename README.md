# Sovereign

Hybrid post-quantum cryptography and a zero-trust plug-in handshake, in three Rust crates.

This is the user-space half of a defence-in-depth design. It covers the parts that can be
built and tested without a kernel module or a radio: the crypto engine, the wire protocol,
and the handshake that decides whether a newly attached device may exist in the system at all.

## What is actually here

| Crate | Responsibility |
| --- | --- |
| `sovereign-crypto` | ML-KEM-1024 + ECDH P-384 KEM, ML-DSA-87 + ECDSA P-384 signatures, HKDF-SHA-384 combiner, XChaCha20-Poly1305 sealing, replay window. |
| `sovereign-ipc` | Versioned, bounds-checked wire protocol: frames, capability tokens, sealed frames, rights bitflags. |
| `sovereign-bridge` | Plug-in handshake state machine, capability narrowing, sessions that emit sealed frames, kernel link, operator CLI. |

## The design rules that matter

**Hybrid means AND, not OR.** A hybrid signature verifies only if *both* the classical and the
post-quantum half verify. OR-composition — accepting either one — hands an attacker the weaker
primitive, which defeats the point. The same rule applies to the KEM: the session key comes from
both shared secrets, with both public keys bound into the HKDF `info` string so a peer cannot
swap one half of the key material.

**Rights are narrowed three times and can only shrink.** What a device gets is
`requested ∩ certificate ∩ platform_ceiling`. `ADMIN` is not in the ceiling, so a hot-plugged
peripheral can never reflash, revoke, or wipe the platform it is attached to. A sensor that asks
for network egress still gets sensor reads only.

**A certificate is not a session.** Holding a valid device certificate proves identity, not
liveness. The device must sign a fresh 32-byte challenge, and the resulting capability token is
bound to that nonce — so a captured handshake cannot be replayed, and a token stolen from one
session is inert in the next.

**The kernel does not trust the bridge.** The bridge mints a capability grant and signs it with
the root key; the kernel verifies that signature itself over the token bytes. A compromised
bridge process can therefore withhold a grant but cannot widen one — escalating the rights field
after signing breaks verification.

**Nothing on the wire is trusted.** The IPC layer validates magic, version, opcode, and declared
length *before* allocating, rejects trailing bytes, and treats every parse error as fatal for the
connection. The link can drop, reorder, or lie; it never gets to assert that a capability is valid.

## Layout

```
crates/sovereign-crypto/src/
  sign.rs     hybrid ECDSA P-384 + ML-DSA-87, AND-composed
  kem.rs      hybrid ML-KEM-1024 + ECDH P-384, HKDF-SHA-384 combiner
  aead.rs     XChaCha20-Poly1305 with caller-supplied nonce forbidden
  replay.rs   IPsec-style sliding window (2048 frames)
  rng.rs      OS entropy, no userspace fallback
crates/sovereign-ipc/src/
  lib.rs      frames, capability tokens, sealed frames, rights
crates/sovereign-bridge/src/
  handshake.rs  quarantine -> challenged -> attested -> active
  session.rs    capability-bound sealing and opening
  link.rs       StreamLink over Read+Write, MockKernel for tests
  main.rs       CLI: ca init / ca certify / enroll / host / verify
```

## Build and test

```sh
cargo test              # 89 tests
cargo clippy --all-targets
cargo build --release
```

## Operator flow

The root key never touches the network. Certificate signing runs offline; only the host command
needs the root seed, and in production that seed belongs in a TPM or HSM.

```sh
# 1. Offline: create the root CA and a device identity.
sovereign-bridge ca init                       # root seeds + public key
sovereign-bridge ca init                       # device seeds + public key

# 2. Offline: certify the device. Its id is derived from its public key.
sovereign-bridge ca certify <root-seed> <device-pubkey> sensor

# 3. On the host: issue a fresh nonce, hand it to the device.
NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# 4. On the device: answer the challenge.
sovereign-bridge enroll <root-pubkey> <device-cert> "$NONCE" <device-seed>

# 5. On the host: verify the claim, narrow rights, mint and self-check the grant.
sovereign-bridge host <root-seed> <device-cert> "$NONCE" <claim> <session-key> <unix-now>

# 6. Anyone can re-verify a grant exactly as the kernel would.
sovereign-bridge verify <root-pubkey> <grant> <unix-now>
```

Seeds are `<ecdsa-seed-hex>:<mldsa-seed-hex>`. Keys are passed on argv for brevity; argv is
readable by every user on the box via `ps`, so production deployments must load them from sealed
storage instead.

## Scope and honest limitations

These are real constraints, not caveats to be waved away:

* **No kernel module.** `link.rs` speaks the frame protocol over any `Read + Write`, which on
  Linux would be a character device from a driver. That driver is not in this repository, so
  IOMMU isolation, DMA zeroization, and the silicon lock are described in the design but not
  implemented or tested here.
* **No network tunnel.** The stealth tunnel (UDP/QUIC mimicry, onion routing, LoRa mesh) is the
  next crate. `SealedFrame` is the exact interface it consumes: sealed bytes plus a counter and
  an epoch, with nothing that reveals length or timing to an observer.
* **Pure-Rust crypto.** The upstream ML-KEM and ML-DSA crates are not constant-time-audited on
  every target and say so. This crate composes them correctly; it does not make them formally
  verified. Independent audit before any production use is not optional.
* **No attestation of the host.** Remote hardware attestation (TPM 2.0, Intel TDX, AMD SEV)
  is designed for but not implemented. Without it, the bridge cannot prove which host it is
  running on, which is a real gap for the server plug-in case.
* **Clocks are assumed roughly monotonic.** Token expiry is checked against a caller-supplied
  timestamp. A host with a broken clock can accept an expired capability; the kernel should
  cross-check against its own monotonic clock.
