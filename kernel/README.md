# kernel/ — plug-in gate

An out-of-tree kernel module that gates access to a character device behind a capability token.

## Honest status first

| Thing | Status |
| --- | --- |
| Compiles against 6.8 headers | Yes, no warnings |
| Ever loaded into a kernel | **No.** `init_module` returns EPERM here (no `CAP_SYS_MODULE`) |
| Core validation logic executed | **Yes** — 11 tests, `make test` |
| IOMMU isolation | **Not implemented** |
| ECDSA / ML-DSA verification | **Not implemented** (uses HMAC-SHA256 instead) |
| TPM / TDX / SEV attestation | **Not implemented** |

The module has never run. Everything below the "what compiles" line is a claim about source
code, not about observed behaviour. If you need this in production, take it to a machine where
you can load modules and someone can review it.

## What is actually there

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

## What the module does not do

The design document describes a device quarantined by the IOMMU before any driver touches it.
This module does not do that. It gates a character device: a process opens `/dev/sovereign_gate`,
writes a grant, and only then may read. A device that is already bound to a driver is not
touched. Real containment needs `iommu_map`/`iommu_unmap`, a device group, and a driver that
actually goes through the gate — none of which are here.

The signature check is HMAC-SHA256 over the token, not the hybrid ECDSA + ML-DSA-87 signature
`sovereign-crypto` produces. Checking a post-quantum signature in kernel space needs a
verifier that does not exist yet. Do not describe this as post-quantum verification.

The root key arrives as a module parameter, which is visible in `/sys/module` and can reach the
kernel log. That is fine for a test rig and not fine for anything else.

## Building

```
make -C kernel            # module, needs kernel headers
make -C kernel test       # core logic tests, needs only a C compiler
```

If Kbuild complains that `gcc-13` is missing, the host compiler differs from the one that built
the kernel; pass `CC=gcc` (which is what this repo does) or install the matching one.
