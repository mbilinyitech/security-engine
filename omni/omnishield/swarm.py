"""A swarm prototype: sharded inference over a binary tensor protocol.

Two nodes each hold part of one weight matrix. Node A sends the input vector as
raw f32 bytes, node B multiplies its shard and returns partial logits, and A
adds them. The sum is exactly the single-node result, which the demo checks to
1e-6.

The same nodes learn online: each sample updates the weights by gradient
descent, and accuracy is measured before and after. A symbolic guard then
refuses an answer whose top-two margin is too small, so the swarm says "I do
not know" instead of guessing.

This is TCP with a 12-byte header and f32 payloads, not UDP/QUIC and not
libp2p. It is a working prototype of the architecture, measured, not the final
transport.
"""

from __future__ import annotations

import json
import math
import random
import socket
import struct
import threading
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

MAGIC = b"OMNI"
VERSION = 1
TENSOR = 1
TEXT = 2
ACK = 3
HEADER = struct.Struct(">4sBBHI")
MAX_PAYLOAD = 4_000_000


class SwarmError(Exception):
    pass


def pack_tensor(vector: Sequence[float], *, kind: int = TENSOR) -> bytes:
    if kind not in (TENSOR, TEXT):
        raise SwarmError("unknown frame kind")
    values = [float(value) for value in vector]
    if len(values) > MAX_PAYLOAD // 4:
        raise SwarmError("the tensor is too large")
    payload = struct.pack(f">{len(values)}f", *values)
    return HEADER.pack(MAGIC, VERSION, kind, 0, len(payload)) + payload


def unpack(frame: bytes) -> dict[str, Any]:
    if len(frame) < HEADER.size:
        raise SwarmError("the frame is shorter than its header")
    magic, version, kind, _flags, length = HEADER.unpack(frame[: HEADER.size])
    if magic != MAGIC:
        raise SwarmError("bad magic")
    if version != VERSION:
        raise SwarmError(f"unsupported version {version}")
    if length > MAX_PAYLOAD or len(frame) - HEADER.size != length:
        raise SwarmError("bad payload length")
    payload = frame[HEADER.size :]
    if kind == TENSOR:
        count = length // 4
        return {"kind": "tensor", "vector": list(struct.unpack(f">{count}f", payload))}
    if kind == TEXT:
        return {"kind": "text", "text": payload.decode("utf-8")}
    raise SwarmError(f"unknown frame kind {kind}")


def json_bytes(vector: Sequence[float]) -> int:
    return len(json.dumps([float(value) for value in vector], separators=(",", ":")).encode("utf-8"))


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise SwarmError("the peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(connection: socket.socket) -> dict[str, Any]:
    header = _recv_exact(connection, HEADER.size)
    magic, version, _kind, _flags, length = HEADER.unpack(header)
    if magic != MAGIC or version != VERSION:
        raise SwarmError("bad header")
    if length > MAX_PAYLOAD:
        raise SwarmError("the frame is too large")
    return unpack(header + _recv_exact(connection, length))


class Shard:
    """Rows [start, start + rows) of a weight matrix, plus their bias."""

    def __init__(self, weights: Sequence[Sequence[float]], bias: Sequence[float], start: int = 0) -> None:
        if not weights or not weights[0]:
            raise SwarmError("a shard needs at least one weight")
        width = len(weights[0])
        if any(len(row) != width for row in weights):
            raise SwarmError("every row must have the same width")
        if len(bias) != len(weights):
            raise SwarmError("the bias must match the rows")
        self.weights = [[float(value) for value in row] for row in weights]
        self.bias = [float(value) for value in bias]
        self.start = int(start)

    @property
    def rows(self) -> int:
        return len(self.weights)

    @property
    def width(self) -> int:
        return len(self.weights[0])

    def partial(self, vector: Sequence[float]) -> list[float]:
        if len(vector) != self.width:
            raise SwarmError(f"expected {self.width} values, got {len(vector)}")
        return [
            sum(weight * value for weight, value in zip(row, vector, strict=True)) + offset
            for row, offset in zip(self.weights, self.bias, strict=True)
        ]

    def train(self, vector: Sequence[float], label: int, *, rate: float = 0.2) -> float:
        logits = self.partial(vector)
        highest = max(logits)
        exps = [math.exp(value - highest) for value in logits]
        total = sum(exps)
        probabilities = [value / total for value in exps]
        if not 0 <= label < len(probabilities):
            raise SwarmError("the label is outside the shard")
        loss = -math.log(max(1e-12, probabilities[label]))
        for row in range(self.rows):
            error = probabilities[row] - (1.0 if row == label else 0.0)
            for column in range(self.width):
                self.weights[row][column] -= rate * error * vector[column]
            self.bias[row] -= rate * error
        return loss

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"start": self.start, "weights": self.weights, "bias": self.bias}),
            encoding="utf-8",
        )
        return target

    @classmethod
    def load(cls, path: str | Path) -> Shard:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(document["weights"], document["bias"], document.get("start", 0))


class SwarmNode:
    def __init__(self, node_id: str, shard: Shard, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if not node_id.strip():
            raise SwarmError("a node needs an id")
        self.id = node_id
        self.shard = shard
        self.host = host
        self.port = port
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.requests = 0

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(16)
        self.server = server
        self.port = server.getsockname()[1]

        def loop() -> None:
            while True:
                try:
                    connection, _ = server.accept()
                except OSError:
                    return
                threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        return self.port

    def _serve(self, connection: socket.socket) -> None:
        with connection:
            try:
                message = _recv_frame(connection)
                if message["kind"] != "tensor":
                    connection.sendall(pack_tensor([], kind=TEXT))
                    return
                self.requests += 1
                connection.sendall(pack_tensor(self.shard.partial(message["vector"])))
            except (SwarmError, OSError):
                return

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            self.server = None

    def partial_from(self, host: str, port: int, vector: Sequence[float], *, timeout: float = 5.0) -> list[float]:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.sendall(pack_tensor(vector))
            reply = _recv_frame(connection)
        if reply["kind"] != "tensor":
            raise SwarmError("the peer did not return a tensor")
        return reply["vector"]

    def infer(self, vector: Sequence[float], peers: Iterable[tuple[str, int]] = ()) -> list[float]:
        partials = [self.shard.partial(vector)]
        for host, port in peers:
            partials.append(self.partial_from(host, port, vector))
        rows = max((len(part) for part in partials), default=0)
        total = [0.0] * rows
        for part in partials:
            for index, value in enumerate(part):
                total[index] += value
        return total


def make_data(*, samples: int = 240, width: int = 6, seed: int = 7) -> list[tuple[list[float], int]]:
    random.seed(seed)
    rows = []
    for index in range(samples):
        label = index % 2
        vector = [random.uniform(-0.2, 0.2) for _ in range(width)]
        vector[label] += 2.0
        rows.append((vector, label))
    return rows


def train_step(shards: Sequence[Shard], vector: Sequence[float], label: int, *, rate: float = 0.3) -> float:
    """One gradient step over the full model, split across shards."""
    logits = [0.0] * sum(shard.rows for shard in shards)
    for shard in shards:
        for index, value in enumerate(shard.partial(vector)):
            logits[shard.start + index] += value
    if not 0 <= label < len(logits):
        raise SwarmError("the label is outside the model")
    highest = max(logits)
    exps = [math.exp(value - highest) for value in logits]
    total = sum(exps)
    probabilities = [value / total for value in exps]
    loss = -math.log(max(1e-12, probabilities[label]))
    for shard in shards:
        for row in range(shard.rows):
            error = probabilities[shard.start + row] - (1.0 if shard.start + row == label else 0.0)
            for column in range(shard.width):
                shard.weights[row][column] -= rate * error * vector[column]
            shard.bias[row] -= rate * error
    return loss


def accuracy(shards: Sequence[Shard], data: Sequence[tuple[list[float], int]]) -> float:
    if not shards or not data:
        raise SwarmError("accuracy needs shards and data")
    size = sum(shard.rows for shard in shards)
    hits = 0
    for vector, label in data:
        logits = [0.0] * size
        for shard in shards:
            for index, value in enumerate(shard.partial(vector)):
                logits[shard.start + index] += value
        if logits.index(max(logits)) == label:
            hits += 1
    return round(hits / len(data), 4)


def guard(logits: Sequence[float], *, margin: float = 0.5) -> dict[str, Any]:
    if not logits or any(math.isnan(value) or math.isinf(value) for value in logits):
        return {"accepted": False, "reason": "non-finite logits", "margin": None}
    ordered = sorted(logits, reverse=True)
    gap = ordered[0] - (ordered[1] if len(ordered) > 1 else ordered[0])
    if gap < margin:
        return {"accepted": False, "reason": "margin below threshold", "margin": round(gap, 4)}
    return {"accepted": True, "reason": "clear margin", "margin": round(gap, 4)}


def demo(*, samples: int = 240) -> dict[str, Any]:
    started = time.perf_counter()
    width, classes = 6, 2
    weights = [[0.0] * width for _ in range(classes)]
    bias = [0.0] * classes
    split = 1
    first = Shard(weights[:split], bias[:split], start=0)
    second = Shard(weights[split:], bias[split:], start=split)
    node_a = SwarmNode("alpha", first)
    node_b = SwarmNode("beta", second)
    node_a.start()
    port_b = node_b.start()
    data = make_data(samples=samples, width=width)
    train, holdout = data[: samples // 2], data[samples // 2 :]
    try:
        vector = train[0][0]
        local = [a + b for a, b in zip(first.partial(vector), second.partial(vector), strict=True)]
        distributed = node_a.infer(vector, [("127.0.0.1", port_b)])
        difference = max(abs(a - b) for a, b in zip(local, distributed, strict=True))

        rounds = 40
        begin = time.perf_counter()
        for _ in range(rounds):
            node_a.infer(vector, [("127.0.0.1", port_b)])
        elapsed = (time.perf_counter() - begin) / rounds
        before = accuracy([first, second], holdout)

        losses = []
        for _ in range(6):
            for sample_vector, label in train:
                losses.append(train_step([first, second], sample_vector, label))
        after = accuracy([first, second], holdout)

        confident = guard([2.4, 0.3])
        unsure = guard([0.2, 0.1])
        broken = guard([float("nan"), 1.0])

        return {
            "protocol": {
                "header_bytes": HEADER.size,
                "tensor_bytes": len(pack_tensor(vector)),
                "json_bytes": json_bytes(vector),
                "saving_x": round(json_bytes(vector) / len(pack_tensor(vector)), 2),
            },
            "shards": {"alpha_rows": first.rows, "beta_rows": second.rows, "width": width},
            "distributed": {
                "matches_local": difference <= 1e-6,
                "max_difference": difference,
                "infer_ms": round(elapsed * 1000, 3),
                "infer_per_s": round(1.0 / elapsed) if elapsed else 0,
                "requests_on_beta": node_b.requests,
            },
            "learning": {
                "train": len(train),
                "holdout": len(holdout),
                "accuracy_before": before,
                "accuracy_after": after,
                "loss_first": round(losses[0], 4),
                "loss_last": round(losses[-1], 4),
            },
            "guard": {"confident": confident, "unsure": unsure, "broken": broken},
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    finally:
        node_a.stop()
        node_b.stop()
