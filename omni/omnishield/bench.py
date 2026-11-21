"""Measured performance for every layer. Run: python3 -m omnishield.bench"""
from __future__ import annotations

import platform
import socket
import statistics
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, x25519

from .hybrid import HybridSigner, HybridVerifier
from .p3_tunnel import EphemeralChannel, RekeyPolicy, client_handshake, server_handshake

MIB = 1024 * 1024
MESSAGE = b"x" * 1024


def _ops_per_second(operation, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        operation()
    return iterations / (time.perf_counter() - start)


def _tunnel_pair(policy: RekeyPolicy):
    client_ratchet = x25519.X25519PrivateKey.generate()
    server_ratchet = x25519.X25519PrivateKey.generate()
    return (
        EphemeralChannel(
            b"c" * 32, b"s" * 32, send_dir=0, own_ratchet=client_ratchet,
            peer_ratchet=server_ratchet.public_key(), policy=policy,
        ),
        EphemeralChannel(
            b"s" * 32, b"c" * 32, send_dir=1, own_ratchet=server_ratchet,
            peer_ratchet=client_ratchet.public_key(), policy=policy,
        ),
    )


def _throughput(size: int, frames: int) -> float:
    client, server = _tunnel_pair(RekeyPolicy(packets=10**9, seconds=10**9))
    payload = b"z" * size
    start = time.perf_counter()
    for _ in range(frames):
        server.open(client.seal(payload))
    return (frames * size) / (time.perf_counter() - start) / MIB


def _handshake_latency(rounds: int = 50) -> float:
    samples: list[float] = []
    for _ in range(rounds):
        server_sock, client_sock = socket.socketpair()

        def serve(sock=server_sock) -> None:
            server_handshake(sock)
            sock.close()

        worker = threading.Thread(target=serve)
        start = time.perf_counter()
        worker.start()
        client_handshake(client_sock)
        samples.append((time.perf_counter() - start) * 1000)
        worker.join()
        client_sock.close()
    return statistics.median(samples)


def main() -> int:
    signer = HybridSigner.generate()
    verifier = HybridVerifier(signer.public_identity)
    envelope = signer.sign(MESSAGE, domain="bench")
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ml_key = mldsa.MLDSA44PrivateKey.generate()
    iterations = 100

    print(f"OmniShield benchmarks — python {platform.python_version()} on {platform.machine()}")
    print(f"signatures over a 1 KiB message, ops/s (n={iterations})")
    print(f"  Ed25519            {_ops_per_second(lambda: ed_key.sign(MESSAGE), iterations):>10.0f}")
    print(f"  ML-DSA-44          {_ops_per_second(lambda: ml_key.sign(MESSAGE), iterations):>10.0f}")
    print(f"  hybrid sign        {_ops_per_second(lambda: signer.sign(MESSAGE, domain='bench'), iterations):>10.0f}")
    print(f"  hybrid verify      {_ops_per_second(lambda: verifier.verify(envelope, MESSAGE, expected_domain='bench'), iterations):>10.0f}")

    rekey_client, _ = _tunnel_pair(RekeyPolicy(packets=1, seconds=10**9))
    print("tunnel")
    print(f"  handshake (median) {_handshake_latency():>10.2f} ms  (includes thread scheduling)")
    print(f"  1 KiB frames       {_throughput(1024, 5000):>10.1f} MiB/s")
    print(f"  64 KiB frames      {_throughput(65536, 500):>10.1f} MiB/s")
    print(f"  rekey (X25519+HKDF){_ops_per_second(lambda: rekey_client.seal(b'x'), 100):>10.0f} /s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
