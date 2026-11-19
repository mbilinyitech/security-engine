# kernel/ — plug-in gate, DMA containment, post-quantum verification

Three out-of-tree modules, all loaded and exercised in a real kernel by `vm/run.sh`.

## Honest status first

| Thing | Status |
| --- | --- |
| Compiles against 6.12 headers | Yes, no warnings |
| Loaded into a real kernel | **Yes** — QEMU q35 VM, `vm/run.sh` |
| Gate logic executed in-kernel | **Yes** — 16 checks |
| IOMMU containment of a PCI device | **Yes** — real DMA lands when mapped, dropped when not |
| ML-DSA-87 verification in kernel space | **Yes** — 8 checks, including a Rust-signed vector |
| ECDSA P-384 verification in kernel space | **No** |
| TPM / TDX / SEV attestation | **No** |

This container cannot load modules (no `CAP_SYS_MODULE`), so `vm/run.sh` boots a QEMU VM with
`intel-iommu` and a QEMU `edu` PCI device and runs the modules there. Every claim in the table
above is backed by a line of VM output, not by a return code from a build.

What is *not* proven: none of this has been reviewed by anyone else, the root key arrives as a
module parameter, and the modules are unsigned. Treat it as a working prototype with tests, not
as a hardened product.

## The three modules

| Module | What it does |
| --- | --- |
| `sovereign_gate.ko` | Gates a character device behind a capability token |
| `sov_iommu.ko` | Puts a PCI device in an empty IOMMU domain and proves the containment with real DMA |
| `sov_mldsa.ko` | Verifies ML-DSA-87 signatures in kernel space |

### `sov_iommu.ko`

Detaches a PCI device from its driver, allocates a fresh `iommu_domain`, attaches the device's
group, and exposes `map`, `unmap`, `state` and `selftest` through sysfs. `state` reports the
device's *actual* domain (`iommu_get_domain_for_dev`), not the module's own pointer — an earlier
version reported the latter and could therefore claim isolation it did not have.

The `selftest` writes to sysfs makes the QEMU `edu` device perform a real DMA:

* with a mapping in place, the device's write lands in the buffer (`dst[0]=0xaa`);
* after the mapping is revoked, the same write is dropped by the IOMMU (`dst[0]=0x0`).

That second half is the whole point. Without it, a verifier that never actually attached the
domain would pass. I checked: removing `iommu_attach_group` makes the selftest fail and the VM
verdict exit non-zero.

### `sov_mldsa.ko`

Verifies ML-DSA-87 (FIPS 204) signatures. Verification only — no signing, no key generation, no
secret material, so a compromised kernel still cannot mint a grant.

The algorithm is the [pq-crystals reference implementation](https://github.com/pq-crystals/dilithium)
(public domain / Apache-2.0), vendored under `mldsa/` and pinned to ML-DSA-87 parameters. I did
not write my own verifier: a hand-written post-quantum implementation that nobody has attacked
is worth less than one that has been reviewed by the cryptographic community for years.

What changed from upstream: the reference keeps ~60 KiB of working state in stack locals, which
overflows the kernel stack, so `mldsa/verify_only.c` allocates one workspace with `kzalloc` and
frees it on every path. Signing and key generation were removed from the build so the module
links no RNG. Nothing else was touched.

The in-kernel selftest checks that a signature produced by the Rust `ml-dsa` crate verifies,
and that tampering with the signature, the message, the public key, `c_tilde`, or the hint is
rejected. The same bytes are checked against the same C code in userspace by
`mldsa/test_cross.c`, and against the Rust signer by `crates/sovereign-crypto/tests/pq_kat.rs`.
Three implementations agreeing is the evidence.

Mutation check: deleting the final `c_tilde` comparison makes the verifier accept everything,
and the VM verdict then fails on two checks. The tests can fail, which is the only thing that
makes passing them meaningful.

## Gate core logic

`sov_core.h` holds all the decisions the gate makes, deliberately free of kernel API calls so it
compiles twice:

* once into the module, where `sov_hmac_sha256` is the kernel's `hmac(sha256)`;
* once into `test_sov_core.c`, which runs on this machine.

That second build is why this is not a pile of unverified code. `make test` checks:

* the 77-byte token layout and every field offset;
* that a wrong length, wrong version or zero rights is refused;
* that expiry is enforced on both sides of the boundary;
* that a single flipped bit in **any** of the 32 tag bytes is caught;
* that a token edited to escalate its own rights breaks the tag;
* that the state machine allows only Quarantined → Active, and that Active and Revoked are
  terminal;
* that the tag compare is constant-time in every byte position.

A separate Rust test (`crates/sovereign-ipc/tests/kernel_layout.rs`) asserts the same offsets
against the real encoder, so the two cannot drift apart without a red test.

## What is still missing

* **The gate still checks HMAC-SHA256, not the hybrid signature.** `sov_mldsa.ko` can verify
  ML-DSA-87, but `sovereign_gate.ko` does not call it yet. Wiring them together needs a grant
  format that carries the public key and both signature halves, which is a wire-format change
  and has not been done. Until then, "the kernel verifies post-quantum signatures" is true of
  `sov_mldsa.ko` and false of the gate.
* **No ECDSA P-384 verifier in kernel space.** The classical half of the hybrid signature is
  still unverified by the kernel.
* **`sov_iommu.ko` contains one device, by BDF.** It does not mediate PCIe enumeration, so a
  device that appears later is not automatically contained. It also does not stop a driver from
  being bound after the module attaches; it relies on nothing else claiming the device.
* **No TPM, TDX or SEV attestation.** A server joining the mesh is not measured.
* **The root key arrives as a module parameter**, visible in `/sys/module` and possibly in the
  kernel log. Fine for a test rig, not fine for anything else.
* **Modules are unsigned.** The VM log shows `module verification failed ... tainting kernel`.

## Building and testing

```
make -C kernel            # the three modules, needs kernel headers
make -C kernel test       # gate core logic, needs only a C compiler
./kernel/vm/run.sh        # boots a VM, loads all three modules, asserts 12 behaviours
```

`vm/run.sh` needs `qemu-system-x86_64`, a static `gcc`, and the kernel image it names at the top
of the script. It mints a real grant with `sovereign-bridge`, builds the initramfs, boots, and
exits non-zero if any check fails.

If Kbuild complains that `gcc-13` is missing, the host compiler differs from the one that built
the kernel; pass `CC=gcc` (which is what this repo does) or install the matching one.
