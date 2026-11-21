"""Move a lot of data quickly, and read air telemetry without pretending.

The transfer path is chunked, checksummed and measured: bytes, seconds and
MB/s are reported, never guessed. Parallel fetch uses threads because the work
is waiting on sockets, not on the CPU.

Software cannot pull oxygen out of the air. What this module does is ingest
telemetry *about* air (O2 %, CO2 ppm, temperature, humidity), keep a rolling
window and raise alerts. `simulate_air` produces plausible readings so the
pipeline can be tested; real readings come from sensors you connect.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .ingest import fetch_url

CHUNK = 1024 * 1024


class StreamError(Exception):
    pass


def chunked_copy(
    source: str | os.PathLike[str],
    sink: str | os.PathLike[str],
    *,
    chunk_size: int = CHUNK,
    verify: bool = True,
) -> dict[str, Any]:
    if chunk_size < 4096:
        raise StreamError("the chunk must be at least 4 KiB")
    origin = Path(source)
    target = Path(sink)
    if not origin.is_file():
        raise StreamError(f"no source at {origin}")
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    moved = 0
    started = time.perf_counter()
    with open(origin, "rb") as reader, open(target, "wb") as writer:
        while True:
            block = reader.read(chunk_size)
            if not block:
                break
            digest.update(block)
            writer.write(block)
            moved += len(block)
    elapsed = time.perf_counter() - started
    result = {
        "bytes": moved,
        "seconds": round(elapsed, 6),
        "mb_per_s": round(moved / elapsed / 1e6, 2) if elapsed else 0.0,
        "sha256": digest.hexdigest(),
        "chunk_size": chunk_size,
        "chunks": -(-moved // chunk_size),
    }
    if verify:
        check = hashlib.sha256()
        with open(target, "rb") as handle:
            for block in iter(lambda: handle.read(chunk_size), b""):
                check.update(block)
        if check.hexdigest() != result["sha256"]:
            raise StreamError("the copy does not match the source")
        result["verified"] = True
    return result


def resume_download(
    url: str,
    path: str | os.PathLike[str],
    *,
    chunk_size: int = CHUNK,
    allow_private: bool = False,
    attempts: int = 5,
) -> dict[str, Any]:
    """Fetch with Range requests, appending to a partial file until complete."""
    import http.client

    from .ingest import USER_AGENT, _validate

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    total = target.stat().st_size if target.is_file() else 0
    rounds = 0
    while rounds < attempts:
        rounds += 1
        scheme, host, request_path, port = _validate(url, allow_private=allow_private)
        connection_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        connection = connection_class(host, port, timeout=20)
        try:
            connection.request(
                "GET",
                request_path,
                headers={"User-Agent": USER_AGENT, "Range": f"bytes={total}-{total + chunk_size - 1}"},
            )
            response = connection.getresponse()
            if response.status == 416:
                break
            if response.status not in (200, 206):
                raise StreamError(f"HTTP {response.status} for {url}")
            if response.status == 200 and total:
                total = 0
            block = response.read(chunk_size)
        finally:
            connection.close()
        if not block:
            break
        with open(target, "ab") as handle:
            handle.write(block)
        total += len(block)
        if len(block) < chunk_size:
            break
    elapsed = time.perf_counter() - started
    digest = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else hashlib.sha256().hexdigest()
    return {
        "path": str(target),
        "bytes": total,
        "rounds": rounds,
        "seconds": round(elapsed, 6),
        "mb_per_s": round(total / elapsed / 1e6, 2) if elapsed else 0.0,
        "sha256": digest,
    }


def parallel_fetch(
    urls: Sequence[str], *, workers: int = 8, allow_private: bool = False, max_bytes: int = CHUNK
) -> dict[str, Any]:
    if not urls:
        raise StreamError("no urls to fetch")
    workers = max(1, min(64, workers))
    started = time.perf_counter()
    results = []

    def one(url: str) -> dict[str, Any]:
        try:
            fetched = fetch_url(url, allow_private=allow_private, max_bytes=max_bytes)
            if fetched["status"] >= 400:
                return {"url": url, "error": f"HTTP {fetched['status']}", "status": fetched["status"], "bytes": 0}
            return {
                "url": url,
                "status": fetched["status"],
                "bytes": len(fetched["body"]),
                "content_type": fetched["content_type"],
                "sha256": hashlib.sha256(fetched["body"]).hexdigest(),
            }
        except Exception as exc:  # noqa: BLE001 - one bad url must not stop the batch
            return {"url": url, "error": str(exc), "bytes": 0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, urls))
    elapsed = time.perf_counter() - started
    moved = sum(item["bytes"] for item in results)
    return {
        "urls": len(urls),
        "workers": workers,
        "ok": sum(1 for item in results if "error" not in item),
        "failed": sum(1 for item in results if "error" in item),
        "bytes": moved,
        "seconds": round(elapsed, 6),
        "mb_per_s": round(moved / elapsed / 1e6, 2) if elapsed else 0.0,
        "results": results,
    }


def disk_benchmark(size_mb: int = 64, *, directory: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    if size_mb < 1 or size_mb > 4096:
        raise StreamError("the benchmark size lives between 1 and 4096 MiB")
    root = Path(directory) if directory else Path(".")
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"omnishield-bench-{os.getpid()}.bin"
    block = os.urandom(CHUNK)
    blocks = size_mb
    try:
        started = time.perf_counter()
        with open(target, "wb") as handle:
            handle.writelines(block for _ in range(blocks))
            handle.flush()
            os.fsync(handle.fileno())
        write_s = time.perf_counter() - started
        started = time.perf_counter()
        read = 0
        with open(target, "rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK), b""):
                read += len(chunk)
        read_s = time.perf_counter() - started
    finally:
        target.unlink(missing_ok=True)
    return {
        "size_mb": size_mb,
        "write_mb_per_s": round(blocks * CHUNK / write_s / 1e6, 2),
        "read_mb_per_s": round(read / read_s / 1e6, 2),
        "write_s": round(write_s, 4),
        "read_s": round(read_s, 4),
    }


def pipeline(lines: Iterable[str], stages: Sequence[Any]) -> dict[str, Any]:
    """Push JSON lines through stages, measuring items per second."""
    started = time.perf_counter()
    passed = 0
    dropped = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            dropped += 1
            continue
        for stage in stages:
            item = stage(item)
            if item is None:
                dropped += 1
                break
        else:
            passed += 1
    elapsed = time.perf_counter() - started
    return {
        "passed": passed,
        "dropped": dropped,
        "seconds": round(elapsed, 6),
        "items_per_s": round((passed + dropped) / elapsed, 1) if elapsed else 0.0,
    }


THRESHOLDS = {"o2_pct": (19.5, 23.5), "co2_ppm": (400.0, 1000.0), "temp_c": (16.0, 28.0), "humidity_pct": (30.0, 70.0)}


class Telemetry:
    """Rolling air telemetry: validate, store as NDJSON, summarise, alert."""

    def __init__(self, path: str | os.PathLike[str], *, window: int = 60) -> None:
        if window < 2:
            raise StreamError("the window needs at least two samples")
        self.path = Path(path)
        self.window = window
        self.samples: list[dict[str, float]] = []
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.samples.append(json.loads(line))

    def ingest(self, sample: Mapping[str, Any]) -> dict[str, Any]:
        clean: dict[str, float] = {}
        for key in THRESHOLDS:
            if key not in sample:
                raise StreamError(f"the sample is missing {key}")
            value = float(sample[key])
            if key == "co2_ppm" and not 100 <= value <= 10_000:
                raise StreamError("co2_ppm is outside the sensor range")
            if key.endswith("_pct") and not 0 <= value <= 100:
                raise StreamError(f"{key} must be a percentage")
            clean[key] = round(value, 3)
        clean["t"] = round(float(sample.get("t", time.time())), 3)
        self.samples.append(clean)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(clean, sort_keys=True) + "\n")
        return clean

    def stats(self, window: int | None = None) -> dict[str, Any]:
        span = self.samples[-(window or self.window) :]
        if not span:
            return {"samples": 0}
        summary: dict[str, Any] = {"samples": len(span)}
        for key in THRESHOLDS:
            values = [row[key] for row in span]
            summary[key] = {
                "mean": round(sum(values) / len(values), 3),
                "min": min(values),
                "max": max(values),
            }
        return summary

    def alerts(self) -> list[dict[str, Any]]:
        found = []
        latest = self.samples[-1] if self.samples else None
        if latest is None:
            return found
        for key, (low, high) in THRESHOLDS.items():
            if latest[key] < low:
                found.append({"metric": key, "value": latest[key], "issue": "below", "limit": low})
            elif latest[key] > high:
                found.append({"metric": key, "value": latest[key], "issue": "above", "limit": high})
        return found


def simulate_air(minutes: int = 60, *, seed: int = 7, rate_hz: float = 1 / 60) -> list[dict[str, float]]:
    """Deterministic, plausible readings: a room with people and a window."""
    if minutes < 1:
        raise StreamError("at least one minute is required")
    state = seed
    rows = []
    count = max(2, int(minutes * 60 * rate_hz))
    for index in range(count):
        state = (state * 6364136223846793005 + 1442695040888963407) % (2**64)
        noise = (state >> 33) / (2**31) - 1.0
        occupancy = 0.5 + 0.5 * (index / count)
        rows.append(
            {
                "t": round(index * 60, 3),
                "o2_pct": round(20.9 - 0.35 * occupancy + 0.05 * noise, 3),
                "co2_ppm": round(450 + 650 * occupancy + 40 * noise, 2),
                "temp_c": round(21.5 + 1.8 * occupancy + 0.2 * noise, 3),
                "humidity_pct": round(44 + 6 * occupancy + 1.5 * noise, 3),
            }
        )
    return rows
