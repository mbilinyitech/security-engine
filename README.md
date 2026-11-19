# Sovereign

Hybrid post-quantum cryptography, a zero-trust plug-in handshake, and a terrestrial transport,
across four Rust crates and one kernel module.

This is the user-space half of a defence-in-depth design. It covers the parts that can be
built and tested without a kernel module or a radio: the crypto engine, the wire protocol,
and the handshake that decides whether a newly attached device may exist in the system at all.

## What is actually here

| Crate | Responsibility |
| --- | --- |
| `sovereign-crypto` | ML-KEM-1024 + ECDH P-384 KEM, ML-DSA-87 + ECDSA P-384 signatures, HKDF-SHA-384 combiner, XChaCha20-Poly1305 sealing, replay window. |
| `sovereign-ipc` | Versioned, bounds-checked wire protocol: frames, capability tokens, sealed frames, rights bitflags. |
| `sovereign-bridge` | Plug-in handshake state machine, capability narrowing, sessions that emit sealed frames, kernel link, operator CLI. |
| `sovereign-tunnel` | Terrestrial transport for sealed frames: UDP with per-peer replay windows, bucket padding, and cover traffic. |
| `kernel/` | Out-of-tree module gating a character device behind a capability token. Compiles; never loaded here. |

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
crates/sovereign-tunnel/src/
  lib.rs        datagram framing, bucket padding, chaff schedule
  replay.rs     per-peer anti-replay window
  transport.rs  real UDP socket, allow-list, replay at the transport
kernel/
  sov_core.h        token parsing, validation, state machine (kernel-free, so it is testable)
  sovereign_gate.c  module glue: chardev, file_operations, hmac(sha256)
  test_sov_core.c   14 tests that run without a kernel
  vm/run.sh         boots a real kernel under QEMU and runs 16 checks against the device
```

## Build and test

```sh
cargo test              # 120 Rust tests
cargo clippy --all-targets -- -D warnings
cargo build --release
make -C kernel test     # 14 C tests for the gate logic
make -C kernel          # builds the module; it cannot be loaded in this container
./kernel/vm/run.sh      # loads it in a real VM and proves it works
```

`kernel/vm/run.sh` is the one that matters. `insmod` fails here with EPERM (no `CAP_SYS_MODULE`),
so the only honest way to test the module is to boot a kernel that will load it. The script
installs nothing you may not have: it needs `qemu-system-x86_64`, a kernel image with matching
headers, `gcc`, `cpio`, and `busybox`. On Debian:

```sh
sudo apt-get install -y qemu-system-x86 busybox-static cpio \
    linux-image-$(uname -r) linux-headers-$(uname -r)
```

It mints a grant with the real bridge, boots, loads, runs the checks, unloads, and exits non-zero
if any of that fails. Current output:

```
  ok   module loaded
  ok   every gate test passed in-kernel
  ok   kernel accepted a sovereign-bridge grant
  ok   module unloaded cleanly
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

* **The kernel module runs in a VM, not on real hardware.** `kernel/vm/run.sh` builds the
  module, boots a stock Debian kernel under QEMU (TCG, no KVM needed), loads it, runs 16 checks
  against `/dev/sovereign_gate`, and unloads it. That covers device registration,
  `file_operations`, `copy_from_user`, the state machine, and the kernel's own `hmac(sha256)`.
  It does **not** cover real hardware, concurrency under load, or anything below the chardev.
  `make -C kernel test` runs 14 further tests against the same decision logic without a kernel.
* **No IOMMU isolation.** The module gates a character device; it does not quarantine a PCIe or
  USB device before a driver binds it. That needs `iommu_map`/`iommu_unmap` and a device group,
  which are not here. A device already bound to a driver bypasses the gate entirely.
* **The module checks HMAC-SHA256, not the hybrid signature.** The bridge signs grants with
  ECDSA P-384 + ML-DSA-87 and verifies that signature; the module then re-checks the grant with
  `hmac(sha256)`. `sovereign-bridge kernel-grant` derives that tag from a grant that already
  passed the hybrid check, so the two layers are sequential rather than equivalent. The gap is
  real: anyone holding the symmetric root key can forge a grant the kernel accepts, and a
  post-quantum verifier in kernel space does not exist yet.
* **The tunnel is a transport, not anonymity.** It gives replay protection, bucket padding, and
  cover traffic over plain UDP. It does not do onion routing, and padding hides length, not
  timing. Traffic analysis against a global observer is out of scope.
* **Pure-Rust crypto.** The upstream ML-KEM and ML-DSA crates are not constant-time-audited on
  every target and say so. This crate composes them correctly; it does not make them formally
  verified. Independent audit before any production use is not optional.
* **No attestation of the host.** Remote hardware attestation (TPM 2.0, Intel TDX, AMD SEV)
  is designed for but not implemented. Without it, the bridge cannot prove which host it is
  running on, which is a real gap for the server plug-in case.
* **Clocks are assumed roughly monotonic.** Token expiry is checked against a caller-supplied
  timestamp. A host with a broken clock can accept an expired capability; the kernel should
  cross-check against its own monotonic clock.
