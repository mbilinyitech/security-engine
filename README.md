# Sovereign

Hybrid post-quantum cryptography, a zero-trust plug-in handshake, a terrestrial transport, an
audit ledger, and a bare-metal Rust kernel, across eight crates, one kernel module, and one
bootable kernel image.

Most of it is user space: the parts that can be built and tested without special hardware. Two
parts are kernel-side and both actually run — a loadable module in a stock kernel, and a
standalone Rust kernel image that boots in QEMU.

## What is actually here

| Crate | Responsibility |
| --- | --- |
| `sovereign-crypto` | ML-KEM-1024 + ECDH P-384 KEM, ML-DSA-87 + ECDSA P-384 signatures, HKDF-SHA-384 combiner, XChaCha20-Poly1305 sealing, replay window. |
| `sovereign-ipc` | Versioned, bounds-checked wire protocol: frames, capability tokens, sealed frames, rights bitflags. |
| `sovereign-bridge` | Plug-in handshake state machine, capability narrowing, sessions that emit sealed frames, kernel link, operator CLI. |
| `sovereign-tunnel` | Terrestrial transport for sealed frames: UDP with per-peer replay windows, bucket padding, and cover traffic. |
| `sovereign-ledger` | Hash-chained append-only audit log with hybrid-signed checkpoints. Every refusal and every grant is recorded, and truncation is detectable. |
| `sovereign-agent` | Capability-gated skills, commands and scripts. Manifests may only name handlers compiled into the binary; they cannot introduce programs. |
| `sovereign-swarm` | Redundant verification with independent checks: gates that veto, and corroborators that must agree. Disagreement is a distinct alarm. |
| `sovereign-interop` | One device protocol, several host transports (Linux chardev, Windows IOCTL shape, macOS IOKit shape), so a device can talk to any OS above the kernel boundary. |
| `kernel/` | Out-of-tree module gating a character device behind a capability token. Compiles; never loaded here. |
| `kernel-rust/` | Bare-metal `no_std` Rust kernel: multiboot entry, page tables, long mode, and the capability gate running with nothing underneath it. Boots in QEMU. |

## The design rules that matter

**Hybrid means AND, not OR.** A hybrid signature verifies only if *both* the classical and the
post-quantum half verify. OR-composition — accepting either one — hands an attacker the weaker
primitive, which defeats the point. The same rule applies to the KEM: the session key comes from
both shared secrets, with both public keys bound into the HKDF `info` string so a peer cannot
swap one half of the key material.

**Three signatures, not two.** `sovereign-crypto::tri` adds SLH-DSA-256s (FIPS 205, hash-based)
alongside ECDSA P-384 and ML-DSA-87, all three required. ECDSA breaks to a quantum computer;
ML-DSA rests on lattice assumptions that are newer than the hash functions SLH-DSA uses. A
forger now has to break a lattice scheme *and* a hash-based one *and* a curve. The cost is real:
SLH-DSA signatures are 29,792 bytes and signing takes roughly half a second, so this belongs on
infrequent operations like certificate issuance, not on every frame.

**Verifier disagreement is an alarm, not a rejection.** `sovereign-swarm` separates two things a
naive design conflates. Gates are independent checks that each may veto; a veto is an ordinary
rejection however many gates agreed. Corroborators are several implementations of the *same*
question, and they must agree — a split means a verifier is broken or an attacker found a
differential, which is the one condition that should page someone. A token that simply expired
trips a gate and is rejected quietly; it does not raise a compromise alarm.

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
crates/sovereign-ledger/src/
  lib.rs        hash-chained entries, signed checkpoints, encode/decode with verification
crates/sovereign-agent/src/
  lib.rs        manifest parser, handler registry, rights check before any step runs
crates/sovereign-swarm/src/
  lib.rs        gates (veto) and corroborators (unanimity), audited verdicts
crates/sovereign-interop/src/
  lib.rs        Transport trait, Linux/Windows/macOS adapters, OS-independent handshake
crates/sovereign-interop/tests/
  full_stack.rs one device through every layer: enrol, seal, tunnel, open, audit, swarm, agent
kernel-rust/
  src/main.rs   multiboot header, PVH note, 32-bit entry, page tables, long mode, kmain
  src/serial.rs polled COM1, no IDT required
  gate-core/    the gate as a no_std library, so it is unit-tested *and* boot-tested
  run.sh        boots the image in QEMU and asserts every expected serial line
kernel/
  sov_core.h        token parsing, validation, state machine (kernel-free, so it is testable)
  sovereign_gate.c  module glue: chardev, file_operations, hmac(sha256)
  test_sov_core.c   14 tests that run without a kernel
  vm/run.sh         boots a real kernel under QEMU and runs 16 checks against the device
```

## Build and test

```sh
cargo test              # 255 Rust tests across eight crates
cargo clippy --all-targets -- -D warnings
cargo build --release
make -C kernel test     # 14 C tests for the gate logic
./kernel-rust/run.sh    # boots the bare-metal kernel in QEMU and asserts 12 lines
make -C kernel          # builds the module; it cannot be loaded in this container
./kernel/vm/run.sh      # loads it in a real VM and proves it works
```

`kernel-rust/run.sh` needs only `qemu-system-x86_64` and a Rust toolchain with
`x86_64-unknown-none`; no GRUB, no cross-compiler, no kernel headers. It builds the image, boots
it, and fails if any expected serial line is missing, so deleting a gate check breaks the build:

```
  ok   sovereign-kernel: long mode entered
  ok   boot: PVH loader confirmed
  ok   gate: valid token admitted ... ok
  ok   gate: replay refused ... ok
  ok   gate: expired token refused ... ok
  ok   gate: quarantined device refused ... ok
  ok   gate: revoked device refused ... ok
  ok   gate: reserved rights refused ... ok
  ok   gate: short token refused ... ok
  ok   gate: least privilege enforced ... ok
  ok   gate: 8 passed, 0 failed
  ok   RESULT: PASS
```

`kernel/vm/run.sh` is the other one that matters. `insmod` fails here with EPERM (no `CAP_SYS_MODULE`),
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
* **IOMMU isolation exists, but only for one device, chosen by BDF.** `sov_iommu.ko` puts a PCI
  device into an empty `iommu_domain` and `vm/run.sh` proves it with real DMA: the device's write
  lands when a buffer is mapped and is dropped by the IOMMU when it is revoked. What it does not
  do is mediate PCIe enumeration, so a device that appears later is not contained automatically,
  and `sovereign_gate.ko` does not go through it. The two modules are independent.
* **The gate checks HMAC-SHA256, not the hybrid signature.** The bridge signs grants with
  ECDSA P-384 + ML-DSA-87 and verifies that signature; the gate then re-checks the grant with
  `hmac(sha256)`. `sovereign-bridge kernel-grant` derives that tag from a grant that already
  passed the hybrid check, so the two layers are sequential rather than equivalent. Anyone
  holding the symmetric root key can still forge a grant the gate accepts.
* **Kernel-space ML-DSA-87 verification works, but nothing calls it yet.** `sov_mldsa.ko`
  verifies ML-DSA-87 (FIPS 204) using the vendored pq-crystals reference, and its in-kernel
  selftest accepts a signature produced by the Rust `ml-dsa` crate and rejects tampered
  variants. `sovereign_gate.ko` does not invoke it: doing so needs a grant wire format that
  carries the public key and both signature halves, which has not been designed. There is still
  no ECDSA P-384 verifier in kernel space, so the hybrid check cannot be completed there.
* **The tunnel is a transport, not anonymity.** It gives replay protection, bucket padding, and
  cover traffic over plain UDP. It does not do onion routing, and padding hides length, not
  timing. Traffic analysis against a global observer is out of scope.
* **Forward secrecy is real; post-compromise security needs a rekey, not a ratchet.** The AEAD
  key is derived with HKDF-SHA-384 from the KEM output, the device id, and the handshake nonce.
  `Session::with_auto_ratchet(n)` advances the epoch every `n` sealed frames, so a caller cannot
  forget to rotate, and `open` follows the peer forward by up to `MAX_EPOCH_SKIP` epochs without
  a caller's help. `Session::rotate` is a *symmetric* step: whoever holds the current key can
  compute every future one. That gives forward secrecy — old frames become unreadable once the
  session has moved two epochs past them — and it gives **nothing** against an attacker who
  already holds the key. Only `Session::rekey`, which mixes in a fresh KEM secret, recovers from
  that, and it requires an actual exchange. The two are separate methods on purpose.
* **One epoch of history is retained, deliberately.** `prev_key` keeps the previous epoch's key
  so a frame reordered across a rotation still opens; it is dropped when the session advances
  again. The cost is precise and worth stating: an attacker who reads receiver memory sees two
  keys instead of one, so they can decrypt one epoch further back than a pure forward-secret
  design would allow. A forward attacker gains nothing from it, because the ratchet is one-way.
  Setting the history to zero would trade this for silent data loss on any reordering.
* **Pure-Rust crypto.** The upstream ML-KEM and ML-DSA crates are not constant-time-audited on
  every target and say so. This crate composes them correctly; it does not make them formally
  verified. Independent audit before any production use is not optional.
* **No attestation of the host.** Remote hardware attestation (TPM 2.0, Intel TDX, AMD SEV)
  is designed for but not implemented. Without it, the bridge cannot prove which host it is
  running on, which is a real gap for the server plug-in case.
* **The bare-metal kernel proves the gate, not an operating system.** `kernel-rust/` boots,
  enters long mode, and runs the capability gate with no allocator, no scheduler, no userspace,
  and no interrupt handlers. It has no IDT, so any fault is a triple fault and a silent reboot.
  That is enough to show the gate logic is sound with nothing underneath it, and it is not an OS:
  a page fault, a malicious device, or a device that needs a driver will all hang or reboot it.
  It is a proof of the boot path and the gate, and should be described as nothing more.
* **"Talks to any OS" is true above the kernel boundary, not below it.** `sovereign-interop`
  shares the wire protocol, the handshake, and the rights logic, and puts the OS-specific part
  behind a two-method trait. The Linux adapter opens a real file descriptor and is tested over a
  real socketpair. The Windows and macOS adapters encode the *shape* of `DeviceIoControl` and
  `IOConnectCallStructMethod` — the control code, the selector, the buffer discipline — but
  contain no FFI to those functions, because that needs each platform's SDK. A single driver
  binary that loads on Linux, Windows and macOS does not exist and is not what this is.
* **The swarm is redundancy, not an AI.** It is a fixed set of checks compiled into the binary,
  chosen because they fail differently: structure, rights ceiling, freshness, digest, and the
  hybrid signature. Nothing rewrites them at run time. A self-modifying verifier cannot be
  audited, and an attacker who can influence its inputs owns it — so the design is deliberately
  the opposite of adaptive, and adding a check is a code change with a test.
* **The audit ledger detects tampering only against an attacker who cannot rewrite the whole
  chain and the checkpoint.** Entries are hash-chained, so editing one breaks every later hash,
  and checkpoints are hybrid-signed so truncation is visible. An attacker with write access to
  the log *and* the ability to replace the checkpoint the verifier trusts can still present a
  shorter valid history. Publish the checkpoint head somewhere else, or the guarantee is weaker
  than it looks.
* **Clocks are assumed roughly monotonic.** Token expiry is checked against a caller-supplied
  timestamp. A host with a broken clock can accept an expired capability; the kernel should
  cross-check against its own monotonic clock.
