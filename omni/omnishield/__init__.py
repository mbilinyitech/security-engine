"""OmniShield: one fail-closed agent runtime.

Contains the four transport layers (air-gap profiles, hardware-rooted identity,
ratcheting tunnel, deterministic allow-list), the hybrid Ed25519 + ML-DSA
signature engine, a Rust core reached over JSON-RPC, durable audited memory,
fail-closed guards, hardware binding that refuses to pretend, and a 500-entry
feature ledger whose evidence is re-checked on demand.

`omnishield status` lists every component; `omnishield doctor` runs them all.
"""

__version__ = "2.0.0"
