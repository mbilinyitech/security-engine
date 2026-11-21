"""Read any file and see every process, with the cost of each call in ms.

Everything here is bounded and honest: a missing kernel interface reports
``available: false`` instead of inventing data, every read is capped, and every
call returns how long it took.
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import time
from pathlib import Path
from typing import Any

from .federation import listening_ports


class InspectError(Exception):
    pass


def _elapsed(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def read_file(
    path: str | os.PathLike[str], *, max_bytes: int = 1_000_000, preview_bytes: int = 4096
) -> dict[str, Any]:
    """Read any file: size, hash, kind and a bounded preview."""
    started = time.perf_counter()
    target = Path(path)
    try:
        stat = target.stat()
    except FileNotFoundError as exc:
        raise InspectError(f"{target} does not exist") from exc
    except PermissionError as exc:
        raise InspectError(f"{target} is not readable: permission denied") from exc
    if target.is_dir():
        raise InspectError(f"{target} is a directory, not a file")
    if max_bytes < 0 or preview_bytes < 0:
        raise InspectError("limits cannot be negative")
    try:
        with open(target, "rb") as handle:
            data = handle.read(max_bytes)
    except PermissionError as exc:
        raise InspectError(f"{target} is not readable: permission denied") from exc
    binary = b"\x00" in data[:preview_bytes]
    preview = data[:preview_bytes]
    document: dict[str, Any] = {
        "path": str(target),
        "size_bytes": stat.st_size,
        "bytes_read": len(data),
        "truncated": stat.st_size > len(data),
        "mode": oct(stat.st_mode & 0o777),
        "mtime_ms": int(stat.st_mtime * 1000),
        "sha256": hashlib.sha256(data).hexdigest(),
        "binary": binary,
    }
    if binary:
        document["preview_hex"] = preview[:512].hex()
        document["lines"] = None
    else:
        text = preview.decode("utf-8", "replace")
        document["preview"] = text
        document["lines"] = text.count("\n")
    document["elapsed_ms"] = _elapsed(started)
    return document


def read_many(
    paths: list[str | os.PathLike[str]], *, max_bytes: int = 1_000_000
) -> dict[str, Any]:
    started = time.perf_counter()
    documents = []
    failures = []
    for path in paths:
        try:
            documents.append(read_file(path, max_bytes=max_bytes))
        except InspectError as exc:
            failures.append({"path": str(path), "error": str(exc)})
    return {
        "files": documents,
        "failures": failures,
        "count": len(documents),
        "total_bytes": sum(item["bytes_read"] for item in documents),
        "elapsed_ms": _elapsed(started),
    }


CLOCK_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def _boot_time_ms() -> int | None:
    source = Path("/proc/stat")
    if not source.is_file():
        return None
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("btime "):
            return int(line.split()[1]) * 1000
    return None


def _parse_stat(content: str, boot_ms: int | None) -> dict[str, Any]:
    head, _, tail = content.rpartition(")")
    fields = tail.split()
    if not fields:
        raise InspectError("malformed /proc stat line")
    rss_pages = int(fields[21])
    page_size = os.sysconf("SC_PAGE_SIZE")
    started_ticks = int(fields[19])
    return {
        "state": fields[0],
        "ppid": int(fields[1]),
        "cpu_seconds": round((int(fields[11]) + int(fields[12])) / CLOCK_TICKS, 3),
        "threads": int(fields[17]),
        "rss_bytes": rss_pages * page_size,
        "started_ms": (boot_ms + int(started_ticks * 1000 / CLOCK_TICKS)) if boot_ms else None,
        "command": head.split("(", 1)[1] if "(" in head else head,
    }


def processes(*, limit: int | None = None) -> dict[str, Any]:
    """Every process, one pass over /proc, timed."""
    started = time.perf_counter()
    root = Path("/proc")
    if not root.is_dir():
        return {
            "available": False,
            "processes": [],
            "count": 0,
            "reason": "no /proc on this system",
            "elapsed_ms": _elapsed(started),
        }
    boot_ms = _boot_time_ms()
    found = []
    for entry in os.scandir(root):
        if not entry.name.isdigit():
            continue
        try:
            content = Path(entry.path, "stat").read_text(encoding="utf-8", errors="replace")
            record = _parse_stat(content, boot_ms)
        except (OSError, InspectError, ValueError, IndexError):
            continue
        record["pid"] = int(entry.name)
        found.append(record)
    found.sort(key=lambda item: item["pid"])
    if limit is not None:
        found = found[:limit]
    return {
        "available": True,
        "processes": found,
        "count": len(found),
        "elapsed_ms": _elapsed(started),
    }


def process(pid: int, *, include_command: bool = True) -> dict[str, Any]:
    started = time.perf_counter()
    base = Path("/proc") / str(pid)
    if not base.is_dir():
        raise InspectError(f"no process with pid {pid}")
    stat = Path(base, "stat").read_text(encoding="utf-8", errors="replace")
    record = _parse_stat(stat, _boot_time_ms())
    record["pid"] = pid
    try:
        record["exe"] = os.readlink(base / "exe")
    except OSError:
        record["exe"] = None
    if include_command:
        try:
            raw = Path(base, "cmdline").read_bytes()
            record["argv"] = [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part]
        except OSError:
            record["argv"] = []
    record["elapsed_ms"] = _elapsed(started)
    return record


def _meminfo() -> dict[str, int]:
    source = Path("/proc/meminfo")
    if not source.is_file():
        return {}
    values = {}
    for line in source.read_text(encoding="utf-8").splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name] = int(parts[0])
    return values


def _cpu_model() -> str | None:
    source = Path("/proc/cpuinfo")
    if not source.is_file():
        return None
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def _thermal() -> list[float]:
    readings = []
    base = Path("/sys/class/thermal")
    if not base.is_dir():
        return readings
    for zone in sorted(base.glob("thermal_zone*")):
        try:
            raw = (zone / "temp").read_text(encoding="utf-8").strip()
            readings.append(round(int(raw) / 1000, 1))
        except (OSError, ValueError):
            continue
    return readings


def snapshot() -> dict[str, Any]:
    """One call, everything the machine can say about itself, timed."""
    started = time.perf_counter()
    memory = _meminfo()
    total = memory.get("MemTotal", 0)
    available = memory.get("MemAvailable", memory.get("MemFree", 0))
    disk = os.statvfs("/")
    disk_total = disk.f_blocks * disk.f_frsize
    disk_free = disk.f_bavail * disk.f_frsize
    ports = listening_ports()
    document: dict[str, Any] = {
        "available": True,
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "cpu_model": _cpu_model(),
        "loadavg": [round(value, 2) for value in os.getloadavg()],
        "memory": {
            "total_kb": total,
            "available_kb": available,
            "used_pct": round(100 * (total - available) / total, 1) if total else None,
        },
        "swap": {
            "total_kb": memory.get("SwapTotal", 0),
            "free_kb": memory.get("SwapFree", 0),
        },
        "disk": {
            "total_bytes": disk_total,
            "free_bytes": disk_free,
            "used_pct": round(100 * (disk_total - disk_free) / disk_total, 1) if disk_total else None,
        },
        "thermal_c": _thermal(),
        "listening_ports": ports["ports"] if ports["available"] else [],
        "process_count": processes(limit=None)["count"],
    }
    document["elapsed_ms"] = _elapsed(started)
    return document


def tree(
    root: str | os.PathLike[str] = ".", *, depth: int = 2, limit: int = 200
) -> dict[str, Any]:
    """Bounded directory walk, so a big tree cannot run away."""
    started = time.perf_counter()
    base = Path(root)
    if not base.is_dir():
        raise InspectError(f"{base} is not a directory")
    if depth < 0 or limit < 1:
        raise InspectError("depth must be >= 0 and limit >= 1")
    entries: list[dict[str, Any]] = []
    stack = [(base, 0)]
    while stack and len(entries) < limit:
        current, level = stack.pop()
        try:
            children = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError:
            continue
        for child in children:
            if len(entries) >= limit:
                break
            try:
                size = child.stat(follow_symlinks=False).st_size
            except OSError:
                size = None
            entries.append(
                {
                    "path": str(Path(child.path).relative_to(base)),
                    "directory": child.is_dir(follow_symlinks=False),
                    "bytes": size,
                    "depth": level + 1,
                }
            )
            if child.is_dir(follow_symlinks=False) and level + 1 < depth:
                stack.append((Path(child.path), level + 1))
    return {
        "root": str(base),
        "entries": entries,
        "count": len(entries),
        "truncated": len(entries) >= limit,
        "elapsed_ms": _elapsed(started),
    }
