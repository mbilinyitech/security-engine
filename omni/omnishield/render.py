"""Draw images and animation on the CPU, with no GPU and no external library.

A canvas is a bytearray of RGB pixels. Shapes are filled with integer spans,
text uses a built-in 5x7 font, PNG is written through ``vision.encode_png`` and
animation is a real GIF89a with an LZW encoder. Everything is deterministic, so
the same call draws the same picture.
"""

from __future__ import annotations

import math
import os
import struct
import time
from collections.abc import Sequence
from itertools import pairwise
from pathlib import Path
from typing import Any

from .stealth import XorShift64
from .vision import encode_png

FONT: dict[str, tuple[str, ...]] = {
    "A": (".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "B": ("####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."),
    "C": (".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."),
    "D": ("####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."),
    "E": ("#####", "#....", "#....", "####.", "#....", "#....", "#####"),
    "F": ("#####", "#....", "#....", "####.", "#....", "#....", "#...."),
    "G": (".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".###."),
    "H": ("#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "I": (".###.", "..#..", "..#..", "..#..", "..#..", "..#..", ".###."),
    "J": ("..###", "...#.", "...#.", "...#.", "...#.", "#..#.", ".##.."),
    "K": ("#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"),
    "L": ("#....", "#....", "#....", "#....", "#....", "#....", "#####"),
    "M": ("#...#", "##.##", "#.#.#", "#...#", "#...#", "#...#", "#...#"),
    "N": ("#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"),
    "O": (".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "P": ("####.", "#...#", "#...#", "####.", "#....", "#....", "#...."),
    "Q": (".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"),
    "R": ("####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"),
    "S": (".####", "#....", "#....", ".###.", "....#", "....#", "####."),
    "T": ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."),
    "U": ("#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "V": ("#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."),
    "W": ("#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"),
    "X": ("#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"),
    "Y": ("#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."),
    "Z": ("#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"),
    "0": (".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."),
    "1": ("..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."),
    "2": (".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"),
    "3": ("####.", "....#", "....#", ".###.", "....#", "....#", "####."),
    "4": ("...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."),
    "5": ("#####", "#....", "####.", "....#", "....#", "#...#", ".###."),
    "6": (".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."),
    "7": ("#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."),
    "8": (".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."),
    "9": (".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."),
    " ": (".....", ".....", ".....", ".....", ".....", ".....", "....."),
    ".": (".....", ".....", ".....", ".....", ".....", ".##..", ".##.."),
    ",": (".....", ".....", ".....", ".....", ".##..", ".##..", ".#..."),
    ":": (".....", ".##..", ".##..", ".....", ".##..", ".##..", "....."),
    "-": (".....", ".....", ".....", "#####", ".....", ".....", "....."),
    "_": (".....", ".....", ".....", ".....", ".....", ".....", "#####"),
    "/": ("....#", "...#.", "...#.", "..#..", ".#...", ".#...", "#...."),
    "%": ("##..#", "##.#.", "...#.", "..#..", ".#...", ".#.##", "#..##"),
    "(": ("...#.", "..#..", ".#...", ".#...", ".#...", "..#..", "...#."),
    ")": (".#...", "..#..", "...#.", "...#.", "...#.", "..#..", ".#..."),
}


class RenderError(Exception):
    pass


class Canvas:
    def __init__(self, width: int, height: int, background: tuple[int, int, int] = (255, 255, 255)) -> None:
        if width < 1 or height < 1:
            raise RenderError("the canvas needs a positive size")
        if width * height > 4_000_000:
            raise RenderError("the canvas is too large for the CPU path")
        self.width = width
        self.height = height
        self.pixels = bytearray(bytes(background) * (width * height))

    def _offset(self, x: int, y: int) -> int:
        return (y * self.width + x) * 3

    def set(self, x: int, y: int, color: tuple[int, int, int]) -> None:
        if 0 <= x < self.width and 0 <= y < self.height:
            offset = self._offset(x, y)
            self.pixels[offset : offset + 3] = bytes(color)

    def get(self, x: int, y: int) -> tuple[int, int, int]:
        offset = self._offset(x, y)
        return tuple(self.pixels[offset : offset + 3])  # type: ignore[return-value]

    def fill_rect(self, x: int, y: int, width: int, height: int, color: tuple[int, int, int]) -> None:
        left = max(0, x)
        right = min(self.width, x + width)
        if right <= left:
            return
        row = bytes(color) * (right - left)
        for row_index in range(max(0, y), min(self.height, y + height)):
            start = (row_index * self.width + left) * 3
            self.pixels[start : start + len(row)] = row

    def rect(self, x: int, y: int, width: int, height: int, color: tuple[int, int, int], thickness: int = 1) -> None:
        self.fill_rect(x, y, width, thickness, color)
        self.fill_rect(x, y + height - thickness, width, thickness, color)
        self.fill_rect(x, y, thickness, height, color)
        self.fill_rect(x + width - thickness, y, thickness, height, color)

    def line(self, x0: int, y0: int, x1: int, y1: int, color: tuple[int, int, int], thickness: int = 1) -> None:
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        error = dx + dy
        half = thickness // 2
        while True:
            if thickness <= 1:
                self.set(x0, y0, color)
            else:
                self.fill_rect(x0 - half, y0 - half, thickness, thickness, color)
            if x0 == x1 and y0 == y1:
                break
            twice = 2 * error
            if twice >= dy:
                error += dy
                x0 += sx
            if twice <= dx:
                error += dx
                y0 += sy

    def circle(self, cx: int, cy: int, radius: int, color: tuple[int, int, int], *, fill: bool = True) -> None:
        if radius < 0:
            raise RenderError("the radius cannot be negative")
        for dy in range(-radius, radius + 1):
            span = int((radius * radius - dy * dy) ** 0.5)
            if fill:
                self.fill_rect(cx - span, cy + dy, 2 * span + 1, 1, color)
            else:
                self.set(cx - span, cy + dy, color)
                self.set(cx + span, cy + dy, color)
                if abs(dy) == radius:
                    self.fill_rect(cx - span, cy + dy, 2 * span + 1, 1, color)

    def polygon(self, points: Sequence[tuple[int, int]], color: tuple[int, int, int]) -> None:
        if len(points) < 3:
            raise RenderError("a polygon needs three points")
        ys = [point[1] for point in points]
        for y in range(max(0, min(ys)), min(self.height, max(ys) + 1)):
            crossings = []
            for index, (x0, y0) in enumerate(points):
                x1, y1 = points[(index + 1) % len(points)]
                if (y0 <= y < y1) or (y1 <= y < y0):
                    crossings.append(x0 + (y - y0) * (x1 - x0) / (y1 - y0))
            crossings.sort()
            for left, right in zip(crossings[0::2], crossings[1::2], strict=False):
                self.fill_rect(int(left), y, max(0, int(right) - int(left) + 1), 1, color)

    def gradient(self, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> None:
        for y in range(self.height):
            ratio = y / max(1, self.height - 1)
            color = tuple(round(top[i] + (bottom[i] - top[i]) * ratio) for i in range(3))
            self.fill_rect(0, y, self.width, 1, color)  # type: ignore[arg-type]

    def text(self, x: int, y: int, message: str, color: tuple[int, int, int], *, scale: int = 1) -> int:
        if scale < 1:
            raise RenderError("the scale must be positive")
        cursor = x
        for character in message.upper():
            glyph = FONT.get(character)
            if glyph is None:
                glyph = FONT[" "]
            for row_index, row in enumerate(glyph):
                for column_index, pixel in enumerate(row):
                    if pixel == "#":
                        self.fill_rect(
                            cursor + column_index * scale,
                            y + row_index * scale,
                            scale,
                            scale,
                            color,
                        )
            cursor += 6 * scale
        return cursor

    def rows(self) -> list[list[tuple[int, int, int]]]:
        return [
            [self.get(x, y) for x in range(self.width)]
            for y in range(self.height)
        ]

    def png(self) -> bytes:
        return encode_png(self.rows())

    def save_png(self, path: str | os.PathLike[str]) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.png())
        return target


def downsample(canvas: Canvas, factor: int = 2) -> Canvas:
    if factor < 2:
        raise RenderError("the factor must be at least two")
    width = canvas.width // factor
    height = canvas.height // factor
    result = Canvas(width, height)
    for y in range(height):
        for x in range(width):
            red = green = blue = 0
            for dy in range(factor):
                for dx in range(factor):
                    r, g, b = canvas.get(x * factor + dx, y * factor + dy)
                    red += r
                    green += g
                    blue += b
            count = factor * factor
            result.set(x, y, (red // count, green // count, blue // count))
    return result


def _quantise(color: tuple[int, int, int]) -> int:
    r, g, b = (min(5, value * 6 // 256) for value in color)
    return r * 36 + g * 6 + b


def _palette() -> bytes:
    entries = bytearray()
    for index in range(216):
        r, g, b = index // 36, (index % 36) // 6, index % 6
        entries.extend((r * 51, g * 51, b * 51))
    entries.extend(bytes(256 * 3 - len(entries)))
    return bytes(entries)


def _lzw(indices: bytes, minimum: int = 8) -> bytes:
    clear, end = 1 << minimum, (1 << minimum) + 1
    table: dict[bytes, int] = {bytes([index]): index for index in range(1 << minimum)}
    next_code = end + 1
    width = minimum + 1
    output = bytearray()
    bit_buffer = 0
    bit_count = 0

    def emit(code: int, bits: int) -> None:
        nonlocal bit_buffer, bit_count
        bit_buffer |= code << bit_count
        bit_count += bits
        while bit_count >= 8:
            output.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bit_count -= 8

    emit(clear, width)
    prefix = b""
    for value in indices:
        symbol = bytes([value])
        candidate = prefix + symbol
        if candidate in table:
            prefix = candidate
            continue
        emit(table[prefix], width)
        if next_code < 4096:
            table[candidate] = next_code
            next_code += 1
            if next_code - 1 == (1 << width) and width < 12:
                width += 1
        else:
            emit(clear, width)
            table = {bytes([index]): index for index in range(1 << minimum)}
            next_code = end + 1
            width = minimum + 1
        prefix = symbol
    if prefix:
        emit(table[prefix], width)
    emit(end, width)
    if bit_count:
        output.append(bit_buffer & 0xFF)
    return bytes(output)


def save_gif(frames: Sequence[Canvas], path: str | os.PathLike[str], *, delay_cs: int = 8) -> Path:
    if not frames:
        raise RenderError("animation needs at least one frame")
    if delay_cs < 0:
        raise RenderError("the delay cannot be negative")
    width, height = frames[0].width, frames[0].height
    if any(frame.width != width or frame.height != height for frame in frames):
        raise RenderError("every frame must have the same size")
    if width > 65535 or height > 65535:
        raise RenderError("the frame is too large for GIF")
    output = bytearray(b"GIF89a")
    output.extend(struct.pack("<HHBBB", width, height, 0xF7, 0, 0))
    output.extend(_palette())
    output.extend(b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00")
    for frame in frames:
        output.extend(b"\x21\xf9\x04\x04")
        output.extend(struct.pack("<H", delay_cs))
        output.extend(b"\x00\x00")
        output.extend(b"\x2c")
        output.extend(struct.pack("<HHHHB", 0, 0, width, height, 0))
        indices = bytes(_quantise(frame.get(x, y)) for y in range(height) for x in range(width))
        compressed = _lzw(indices)
        output.extend(b"\x02")
        output.extend(struct.pack("<H", len(compressed)))
        output.extend(compressed)
    output.extend(b"\x3b")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes(output))
    return target


def chart(
    series: Sequence[float],
    *,
    width: int = 480,
    height: int = 260,
    title: str = "Series",
    color: tuple[int, int, int] = (31, 119, 180),
) -> Canvas:
    if not series:
        raise RenderError("a chart needs at least one value")
    canvas = Canvas(width, height)
    canvas.gradient((248, 250, 252), (226, 232, 240))
    canvas.fill_rect(40, 30, width - 60, height - 70, (255, 255, 255))
    canvas.text(44, 8, title[: (width - 60) // 6], (30, 41, 59))
    low, high = min(series), max(series)
    span = (high - low) or 1.0
    plot_width, plot_height = width - 70, height - 90
    canvas.line(40, 30 + plot_height, 40 + plot_width, 30 + plot_height, (100, 116, 139))
    canvas.line(40, 30, 40, 30 + plot_height, (100, 116, 139))
    if len(series) == 1:
        canvas.circle(40 + plot_width // 2, 30 + plot_height // 2, 4, color)
    else:
        step = plot_width / (len(series) - 1)
        points = [
            (
                40 + round(index * step),
                30 + plot_height - round((value - low) / span * plot_height),
            )
            for index, value in enumerate(series)
        ]
        for (x0, y0), (x1, y1) in pairwise(points):
            canvas.line(x0, y0, x1, y1, color, thickness=2)
    canvas.text(44, height - 20, f"MIN {low:.2f}  MAX {high:.2f}", (71, 85, 105))
    return canvas


def art(seed: int = 7, *, width: int = 320, height: int = 200) -> Canvas:
    generator = XorShift64(seed)
    canvas = Canvas(width, height)
    canvas.gradient((15, 23, 42), (56, 189, 248))
    for _ in range(18):
        x = generator.next_u64() % width
        y = generator.next_u64() % height
        radius = 8 + generator.next_u64() % 40
        hue = generator.next_u64() % 3
        color = ((230, 120, 60), (120, 200, 160), (200, 180, 90))[hue]
        canvas.circle(x, y, radius, color, fill=False)
    for _ in range(6):
        points = [
            (generator.next_u64() % width, generator.next_u64() % height) for _ in range(3)
        ]
        canvas.polygon(points, (255, 255, 255))
    canvas.text(10, height - 14, f"SEED {seed}", (255, 255, 255))
    return canvas


def animate(*, frames: int = 12, width: int = 160, height: int = 100, seed: int = 3) -> list[Canvas]:
    if frames < 2:
        raise RenderError("an animation needs at least two frames")
    canvas_frames = []
    for index in range(frames):
        canvas = Canvas(width, height)
        canvas.gradient((8, 47, 73), (125, 211, 252))
        x = 10 + index * (width - 40) // max(1, frames - 1)
        canvas.circle(x, height // 2, 10, (250, 204, 21))
        canvas.fill_rect(0, height - 12, width, 12, (21, 94, 117))
        canvas.text(6, 6, f"FRAME {index + 1}", (241, 245, 249))
        canvas_frames.append(canvas)
    return canvas_frames


def read_ppm(data: bytes) -> tuple[int, int, list[list[tuple[int, int, int]]]]:
    """Read a binary P6 PPM, the format the Rust core writes."""
    if not data.startswith(b"P6"):
        raise RenderError("not a binary PPM")
    fields: list[int] = []
    position = 2
    while len(fields) < 3:
        while position < len(data) and data[position : position + 1].isspace():
            position += 1
        if data[position : position + 1] == b"#":
            while position < len(data) and data[position : position + 1] != b"\n":
                position += 1
            continue
        start = position
        while position < len(data) and not data[position : position + 1].isspace():
            position += 1
        fields.append(int(data[start:position]))
    position += 1
    width, height, maximum = fields
    if maximum != 255:
        raise RenderError("only 8-bit PPM is supported")
    payload = data[position : position + width * height * 3]
    if len(payload) != width * height * 3:
        raise RenderError("the PPM payload is short")
    rows = []
    for y in range(height):
        row = []
        for x in range(width):
            offset = (y * width + x) * 3
            row.append((payload[offset], payload[offset + 1], payload[offset + 2]))
        rows.append(row)
    return width, height, rows


def load_palette(path: str | os.PathLike[str] | None = None) -> list[tuple[int, int, int]]:
    """Read the five RGB stops that analysis/palette.R writes, when present."""
    target = Path(path) if path else Path(__file__).resolve().parent.parent / "analysis" / "data" / "palette.csv"
    if not target.is_file():
        return [(10, 15, 33), (41, 56, 115), (216, 115, 56), (250, 199, 89), (237, 242, 251)]
    rows = []
    for line in target.read_text(encoding="utf-8").splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split(",")
        rows.append((int(parts[1]), int(parts[2]), int(parts[3])))
    return rows or [(10, 15, 33), (41, 56, 115), (216, 115, 56), (250, 199, 89), (237, 242, 251)]


def _scene_python(width: int, height: int, samples: int) -> Canvas:
    night, sea, ember, gold, _light = load_palette()
    canvas = Canvas(width, height)
    for y in range(height):
        v = y / max(1, height - 1)
        if v < 0.58:
            ratio = (v / 0.58) ** 1.3
            top, bottom = night, ember
        else:
            ratio = ((v - 0.58) / 0.42) ** 0.8
            top, bottom = sea, night
        color = tuple(round(top[i] + (bottom[i] - top[i]) * ratio) for i in range(3))
        canvas.fill_rect(0, y, width, 1, color)  # type: ignore[arg-type]
    canvas.circle(int(width * 0.30), int(height * 0.50), max(4, width // 40), gold)
    canvas.circle(int(width * 0.30), int(height * 0.50), max(8, width // 14), gold, fill=False)
    for x in range(width):
        ridge = int(height * (0.62 + 0.05 * math.sin(x / width * 7)))
        canvas.fill_rect(x, ridge, 1, height - ridge, (14, 22, 46))
    for x in range(width):
        near = int(height * (0.74 + 0.03 * math.sin(x / width * 5 + 1.3)))
        canvas.fill_rect(x, near, 1, height - near, (9, 14, 30))
    return canvas


def scene(
    width: int = 480,
    height: int = 300,
    *,
    samples: int = 2,
    engine: str = "auto",
    binary: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Render the landscape scene, preferring the Rust core when it is built.

    The Rust path supersamples ``samples`` per axis. The pure-Python fallback
    draws one sample per pixel and reports ``samples: 1`` rather than pretending.
    """
    if samples < 1:
        raise RenderError("at least one sample per axis is required")
    if engine not in {"auto", "rust", "python"}:
        raise RenderError("engine is auto, rust or python")
    started = time.perf_counter()
    if engine in {"auto", "rust"}:
        executable = Path(binary) if binary else Path(__file__).resolve().parent.parent / "organism" / "target" / "release" / "organism"
        if executable.is_file() and os.access(executable, os.X_OK):
            import json
            import subprocess
            import tempfile

            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "scene.ppm"
                completed = subprocess.run(
                    [str(executable), "render", str(width), str(height), str(samples), str(target)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if completed.returncode != 0:
                    raise RenderError(f"the Rust renderer failed: {completed.stderr.strip()}")
                document = json.loads(completed.stdout)
                parsed_width, parsed_height, rows = read_ppm(target.read_bytes())
            canvas = Canvas(parsed_width, parsed_height)
            for y, row in enumerate(rows):
                for x, pixel in enumerate(row):
                    canvas.set(x, y, pixel)
            return {
                "canvas": canvas,
                "engine": "rust",
                "elapsed_ms": document["elapsed_ms"],
                "pixels_per_second": document["pixels_per_second"],
                "wall_ms": round((time.perf_counter() - started) * 1000, 3),
                "samples": samples,
            }
        if engine == "rust":
            raise RenderError("the Rust binary is not built")
    canvas = _scene_python(width, height, samples)
    elapsed = (time.perf_counter() - started) * 1000
    return {
        "canvas": canvas,
        "engine": "python",
        "elapsed_ms": round(elapsed, 3),
        "pixels_per_second": round(width * height / (elapsed / 1000), 1),
        "wall_ms": round(elapsed, 3),
        "samples": 1,
    }


def quality_metrics(canvas: Canvas) -> dict[str, Any]:
    """Contrast, saturation, edge energy and colour count, measured on the pixels."""
    luminance = []
    saturation = []
    colours = set()
    for y in range(canvas.height):
        for x in range(canvas.width):
            r, g, b = canvas.get(x, y)
            luminance.append(0.2126 * r + 0.7152 * g + 0.0722 * b)
            high, low = max(r, g, b), min(r, g, b)
            saturation.append(0.0 if high == 0 else (high - low) / high)
            colours.add((r, g, b))
    ordered = sorted(luminance)
    count = len(ordered)
    low = ordered[int(count * 0.05)]
    high = ordered[int(count * 0.95) - 1]
    edges = 0.0
    for y in range(1, canvas.height - 1):
        for x in range(1, canvas.width - 1):
            gx = luminance[y * canvas.width + x + 1] - luminance[y * canvas.width + x - 1]
            gy = luminance[(y + 1) * canvas.width + x] - luminance[(y - 1) * canvas.width + x]
            edges += abs(gx) + abs(gy)
    mean = sum(luminance) / count
    variance = sum((value - mean) ** 2 for value in luminance) / count
    return {
        "width": canvas.width,
        "height": canvas.height,
        "mean_luminance": round(mean, 2),
        "std_luminance": round(math.sqrt(variance), 2),
        "contrast": round(high - low, 2),
        "saturation": round(sum(saturation) / count, 4),
        "edge_energy": round(edges / count, 2),
        "unique_colours": len(colours),
    }


def noise_level(canvas: Canvas, radius: int = 1) -> float:
    """Mean absolute difference from a box blur: a cheap grain estimate."""
    total = 0.0
    count = 0
    for y in range(radius, canvas.height - radius):
        for x in range(radius, canvas.width - radius):
            for channel in range(3):
                value = canvas.get(x, y)[channel]
                mean = 0.0
                for dy in range(-radius, radius + 1):
                    for dx in range(-radius, radius + 1):
                        mean += canvas.get(x + dx, y + dy)[channel]
                mean /= (2 * radius + 1) ** 2
                total += abs(value - mean)
                count += 1
    return round(total / max(1, count), 3)


def denoise(canvas: Canvas, *, radius: int = 2, sigma_color: float = 18.0, sigma_space: float = 2.0) -> Canvas:
    """Edge-preserving bilateral filter, so grain drops but edges stay."""
    if radius < 1:
        raise RenderError("the radius must be positive")
    output = Canvas(canvas.width, canvas.height)
    spatial = [
        (dx, dy, math.exp(-(dx * dx + dy * dy) / (2 * sigma_space * sigma_space)))
        for dy in range(-radius, radius + 1)
        for dx in range(-radius, radius + 1)
    ]
    for y in range(canvas.height):
        for x in range(canvas.width):
            centre = canvas.get(x, y)
            total = [0.0, 0.0, 0.0]
            weight_sum = 0.0
            for dx, dy, space_weight in spatial:
                sx = min(max(x + dx, 0), canvas.width - 1)
                sy = min(max(y + dy, 0), canvas.height - 1)
                pixel = canvas.get(sx, sy)
                difference = sum((pixel[channel] - centre[channel]) ** 2 for channel in range(3)) / 3
                weight = space_weight * math.exp(-difference / (2 * sigma_color * sigma_color))
                for channel in range(3):
                    total[channel] += pixel[channel] * weight
                weight_sum += weight
            output.set(x, y, tuple(round(value / weight_sum) for value in total))
    return output
