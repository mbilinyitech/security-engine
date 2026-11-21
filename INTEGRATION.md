# Omni inside Sovereign

`omni/` is the OmniShield stack, integrated with Sovereign (`security-engine`).
Both stay independently buildable; the bridge is one Python module that calls
Sovereign's operator CLI.

## Layout

| Path | What it is |
| --- | --- |
| `crates/` | Sovereign's eight Rust crates (hybrid PQ crypto, IPC, bridge, tunnel, ledger, agent, swarm, interop) |
| `kernel/`, `kernel-rust/` | The C kernel module and the bare-metal Rust kernel |
| `omni/` | OmniShield: Rust `organism` core, Python `omnishield`, corpus, scenes, tests, R analysis |

## Build

```console
$ cargo build --release -p sovereign-bridge
$ cd omni && cargo build --manifest-path organism/Cargo.toml --release
```

`omni/organism` declares its own empty `[workspace]` so it is not pulled into
Sovereign's workspace.

## The bridge

`omni/omnishield/sovereign.py` runs the real pipeline:

```
ca init (root) -> ca init (device) -> ca certify -> enroll -> host -> verify
```

Measured: six stages, a 4,804-byte grant, `valid=true`, 32.1 ms. The grant is
signed with **both** ECDSA P-384 and ML-DSA-87; Sovereign's rule is AND, not OR.

```console
$ cd omni && python3 -m omnishield sovereign status
$ cd omni && python3 -m omnishield sovereign pipeline --rights telemetry
```

## Checks

```console
$ make omni-test        # Python tests
$ make omni-doctor      # 64/64 checks
$ ./scripts/omni.sh     # doctor, tests and the capability pipeline
```

## What is shared and what is not

Shared: the capability concept (Sovereign issues, Omni verifies), the hybrid
signature rule, and the audit mindset.

Not shared yet: Omni's OmniNet envelopes still use Ed25519, not Sovereign's
hybrid signature; Omni's swarm does not use Sovereign's verification swarm; and
Omni's skills are not registered in Sovereign's capability-gated agent. Those
are the next three integration steps, each measurable.
