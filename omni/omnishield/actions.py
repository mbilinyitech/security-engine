"""Actions that act, safely, with no dependency.

A jailed file system, an AST calculator, an allow-listed command runner, tool
composition and repair, an HTTP client pinned to allowed hosts, SQLite queries,
an SVG chart writer, PNG and WAV generation, and a differential-drive robot with
a PID loop.
"""

from __future__ import annotations

import ast
import math
import operator
import os
import re
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import wave
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .vision import encode_png


class ActionError(Exception):
    pass


class SafeFS:
    """Every path is resolved and must stay under the root."""

    def __init__(self, root: str | os.PathLike[str], *, max_bytes: int = 1_000_000) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    def _resolve(self, relative: str) -> Path:
        target = (self.root / relative).resolve()
        if target != self.root and self.root not in target.parents:
            raise ActionError(f"{relative!r} escapes the sandbox")
        return target

    def write(self, relative: str, data: str | bytes) -> dict[str, Any]:
        payload = data.encode("utf-8") if isinstance(data, str) else data
        if len(payload) > self.max_bytes:
            raise ActionError("the payload is larger than the sandbox limit")
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return {"path": str(target.relative_to(self.root)), "bytes": len(payload)}

    def read(self, relative: str) -> str:
        target = self._resolve(relative)
        if not target.is_file():
            raise ActionError(f"{relative!r} is not a file")
        return target.read_text(encoding="utf-8")

    def list(self, relative: str = ".") -> list[str]:
        target = self._resolve(relative)
        if not target.is_dir():
            raise ActionError(f"{relative!r} is not a directory")
        return sorted(
            str(item.relative_to(self.root)) for item in target.iterdir()
        )

    def delete(self, relative: str) -> dict[str, Any]:
        target = self._resolve(relative)
        if not target.is_file():
            raise ActionError(f"{relative!r} is not a file")
        target.unlink()
        return {"deleted": str(target.relative_to(self.root))}


_BINARY = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}
_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "sum": sum,
    "sqrt": math.sqrt,
    "log": math.log,
    "sin": math.sin,
    "cos": math.cos,
}


def calculate(expression: str) -> dict[str, Any]:
    """Evaluate arithmetic from an AST; names and attributes are refused."""
    if not expression.strip() or len(expression) > 500:
        raise ActionError("the expression is empty or too long")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ActionError(f"cannot parse the expression: {exc.msg}") from exc

    def walk(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
            return _BINARY[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            return _UNARY[type(node.op)](walk(node.operand))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id not in _FUNCTIONS or node.keywords:
                raise ActionError(f"{node.func.id!r} is not allowed")
            return _FUNCTIONS[node.func.id](*[walk(argument) for argument in node.args])
        if isinstance(node, ast.Tuple):
            return tuple(walk(element) for element in node.elts)
        raise ActionError(f"{type(node).__name__} is not allowed")

    try:
        value = walk(tree)
    except ZeroDivisionError as exc:
        raise ActionError("division by zero") from exc
    return {"value": value, "type": type(value).__name__}


def run_command(
    argv: Sequence[str],
    *,
    allowed: Iterable[str],
    cwd: str | os.PathLike[str] | None = None,
    timeout: float = 10.0,
    max_output: int = 4000,
) -> dict[str, Any]:
    """No shell, an explicit executable allow-list, bounded output."""
    if not argv:
        raise ActionError("a command needs at least one argument")
    executable = os.path.basename(argv[0])
    if executable not in set(allowed):
        raise ActionError(f"{executable!r} is not on the allow-list")
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timed out", "timed_out": True}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout[:max_output],
        "stderr": completed.stderr[:max_output],
        "timed_out": False,
    }


def execute_python(source: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Run a snippet in an isolated interpreter; not a security boundary."""
    return run_command(
        [sys.executable, "-I", "-c", source],
        allowed={os.path.basename(sys.executable), "python3", "python"},
        timeout=timeout,
    )


def compose(
    tools: Mapping[str, Mapping[str, Any]], pipeline: Sequence[str], *, initial: Any
) -> dict[str, Any]:
    """Chain tools, refusing any step whose input type does not match."""
    value = initial
    kind = type(value).__name__
    steps = []
    for name in pipeline:
        if name not in tools:
            raise ActionError(f"unknown tool {name!r}")
        tool = tools[name]
        expected = tool.get("input")
        if expected and expected != kind:
            raise ActionError(f"{name!r} expects {expected}, got {kind}")
        value = tool["run"](value)
        kind = type(value).__name__
        steps.append({"tool": name, "type": kind, "value": value})
    return {"value": value, "type": kind, "steps": steps}


def _coerce(value: Any, wanted: type | None) -> Any:
    if wanted is None or value is None:
        return value
    if wanted is int and isinstance(value, str):
        return int(value)
    if wanted is float and isinstance(value, str):
        return float(value)
    if wanted is str and not isinstance(value, str):
        return str(value)
    if wanted is bool and isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return value


def repair(
    tool: Callable[..., Any],
    arguments: Mapping[str, Any],
    *,
    schema: Mapping[str, type] | None = None,
    defaults: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Try the call, then coerce, then drop unknown keys, then fill defaults."""
    schema = schema or {}
    defaults = defaults or {}
    attempts: list[dict[str, str]] = []
    candidates: list[tuple[str, dict[str, Any]]] = [("as_given", dict(arguments))]
    if schema:
        candidates.append(
            ("coerced", {key: _coerce(value, schema.get(key)) for key, value in arguments.items()})
        )
        candidates.append(
            ("dropped_unknown", {key: value for key, value in arguments.items() if key in schema})
        )
        candidates.append(
            (
                "defaults",
                {
                    **defaults,
                    **{key: value for key, value in arguments.items() if key in schema},
                },
            )
        )
    for name, kwargs in candidates:
        try:
            result = tool(**kwargs)
        except Exception as exc:  # noqa: BLE001 - a tool may raise anything; the repair ladder handles it
            attempts.append({"repair": name, "error": f"{type(exc).__name__}: {exc}"})
            continue
        return {
            "ok": True,
            "repair": name,
            "result": result,
            "attempts": len(attempts) + 1,
            "errors": attempts,
        }
    return {"ok": False, "repair": None, "attempts": len(attempts), "errors": attempts}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_get(
    url: str,
    *,
    allowed_hosts: Iterable[str],
    timeout: float = 5.0,
    max_bytes: int = 200_000,
) -> dict[str, Any]:
    """Host allow-list, no redirects, bounded body."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ActionError("only http and https are allowed")
    if parsed.hostname not in set(allowed_hosts):
        raise ActionError(f"{parsed.hostname!r} is not on the host allow-list")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "omnishield/1"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes)
            return {
                "status": response.status,
                "body": body.decode("utf-8", "replace"),
                "truncated": len(body) == max_bytes,
            }
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": "", "truncated": False}
    except urllib.error.URLError as exc:
        raise ActionError(f"request failed: {exc.reason}") from exc


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def sqlite_query(
    rows: Sequence[Mapping[str, Any]], sql: str, *, table: str = "data"
) -> dict[str, Any]:
    if not _IDENTIFIER.match(table):
        raise ActionError("the table name must be a plain identifier")
    if not rows:
        raise ActionError("no rows to load")
    columns = list(rows[0])
    if any(not _IDENTIFIER.match(column) for column in columns):
        raise ActionError("column names must be plain identifiers")
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            f"CREATE TABLE {table} ({', '.join(f'{column} TEXT' for column in columns)})"
        )
        connection.executemany(
            f"INSERT INTO {table} VALUES ({', '.join('?' for _ in columns)})",
            [tuple(str(row[column]) for column in columns) for row in rows],
        )
        cursor = connection.execute(sql)
        if cursor.description is None:
            connection.commit()
            return {"columns": [], "rows": [], "count": cursor.rowcount}
        names = [description[0] for description in cursor.description]
        result = [dict(zip(names, values)) for values in cursor.fetchall()]
        return {"columns": names, "rows": result, "count": len(result)}
    finally:
        connection.close()


def describe(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        raise ActionError("no values")
    ordered = sorted(values)
    count = len(ordered)
    mean = sum(ordered) / count
    median = (
        ordered[count // 2]
        if count % 2
        else (ordered[count // 2 - 1] + ordered[count // 2]) / 2
    )
    variance = sum((value - mean) ** 2 for value in ordered) / count
    return {
        "count": count,
        "mean": round(mean, 4),
        "median": round(median, 4),
        "stdev": round(math.sqrt(variance), 4),
        "min": min(ordered),
        "max": max(ordered),
    }


def svg_chart(
    series: Mapping[str, Sequence[float]],
    *,
    width: int = 480,
    height: int = 240,
    padding: int = 24,
) -> str:
    """A deterministic line chart as SVG text."""
    if not series:
        raise ActionError("no series")
    values = [value for points in series.values() for value in points]
    low, high = min(values), max(values)
    span = high - low or 1.0
    inner_width = width - 2 * padding
    inner_height = height - 2 * padding
    opening = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
    )
    parts = [opening, f'<rect width="{width}" height="{height}" fill="#ffffff"/>']
    palette = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e"]
    for index, (name, points) in enumerate(series.items()):
        if len(points) < 2:
            continue
        coordinates = []
        for position, value in enumerate(points):
            x = padding + inner_width * position / (len(points) - 1)
            y = padding + inner_height * (1 - (value - low) / span)
            coordinates.append(f"{x:.1f},{y:.1f}")
        colour = palette[index % len(palette)]
        parts.append(
            f'<polyline fill="none" stroke="{colour}" stroke-width="2" points="'
            + " ".join(coordinates)
            + '"/>'
        )
        parts.append(
            
                f'<text x="{padding}" y="{padding + 12 * (index + 1)}" font-size="11" '
                f'fill="{colour}">{name}</text>'
            
        )
    parts.append("</svg>")
    return "\n".join(parts)


def render_png(
    width: int, height: int, *, shade: Callable[[int, int], tuple[int, int, int]]
) -> bytes:
    if width < 1 or height < 1:
        raise ActionError("the image needs a positive size")
    image = [[shade(x, y) for x in range(width)] for y in range(height)]
    return encode_png(image)


def write_wav(
    path: str | os.PathLike[str], samples: Sequence[float], *, rate: int = 8000
) -> dict[str, Any]:
    if not samples:
        raise ActionError("no samples")
    clipped = [max(-32768, min(32767, int(value))) for value in samples]
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(b"".join(int(value).to_bytes(2, "little", signed=True) for value in clipped))
    return {"path": str(path), "samples": len(clipped), "rate": rate}


def tone(frequency: float, *, rate: int = 8000, seconds: float = 0.5, amplitude: float = 0.5) -> list[int]:
    count = int(rate * seconds)
    return [
        int(32767 * amplitude * math.sin(2 * math.pi * frequency * index / rate))
        for index in range(count)
    ]


@dataclass
class DifferentialDrive:
    wheel_base: float = 0.5
    x: float = 0.0
    y: float = 0.0
    theta: float = 0.0
    trail: list[tuple[float, float]] = field(default_factory=list)

    def step(self, left: float, right: float, *, dt: float = 0.1) -> dict[str, float]:
        forward = (left + right) / 2.0
        turn = (right - left) / self.wheel_base
        self.x += forward * math.cos(self.theta) * dt
        self.y += forward * math.sin(self.theta) * dt
        self.theta += turn * dt
        self.trail.append((round(self.x, 4), round(self.y, 4)))
        return {"x": round(self.x, 4), "y": round(self.y, 4), "theta": round(self.theta, 4)}

    def run(self, commands: Sequence[tuple[float, float]], *, dt: float = 0.1) -> dict[str, Any]:
        for left, right in commands:
            self.step(left, right, dt=dt)
        return {
            "pose": {"x": round(self.x, 4), "y": round(self.y, 4), "theta": round(self.theta, 4)},
            "steps": len(commands),
            "trail": self.trail,
        }


def pid_step(
    error: float,
    *,
    integral: float = 0.0,
    previous_error: float = 0.0,
    kp: float = 1.0,
    ki: float = 0.1,
    kd: float = 0.05,
    dt: float = 1.0,
) -> dict[str, float]:
    integral += error * dt
    derivative = (error - previous_error) / dt if dt else 0.0
    output = kp * error + ki * integral + kd * derivative
    return {
        "output": round(output, 4),
        "integral": round(integral, 4),
        "previous_error": error,
    }

