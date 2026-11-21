"""Vision and perception without a dependency.

A real PNG decoder and encoder (zlib, all five scanline filters), grayscale and
blur, Sobel edges, thresholding, connected components, center-surround saliency,
normalised template matching, frame differencing, softmax attention, modality
fusion, habituation and adaptation, plus WAV reading and a radix-2 FFT.
"""

from __future__ import annotations

import math
import struct
import wave
import zlib
from collections.abc import Sequence
from itertools import pairwise
from typing import Any


class VisionError(Exception):
    pass


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def encode_png(image: Sequence[Sequence[Any]], *, gray: bool = False) -> bytes:
    """Encode rows of ints (gray) or (r, g, b) tuples into a PNG."""
    if not image or not image[0]:
        raise VisionError("an image needs at least one pixel")
    height = len(image)
    width = len(image[0])
    if any(len(row) != width for row in image):
        raise VisionError("every row must have the same width")
    raw = bytearray()
    for row in image:
        raw.append(0)
        if gray:
            raw.extend(max(0, min(255, int(value))) for value in row)
        else:
            for pixel in row:
                if len(pixel) != 3:
                    raise VisionError("colour pixels need three channels")
                raw.extend(max(0, min(255, int(value))) for value in pixel)
    header = struct.pack(">IIBBBBB", width, height, 8, 0 if gray else 2, 0, 0, 0)
    return (
        PNG_SIGNATURE
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + _chunk(b"IEND", b"")
    )


def _paeth(left: int, above: int, corner: int) -> int:
    estimate = left + above - corner
    distances = (abs(estimate - left), abs(estimate - above), abs(estimate - corner))
    if distances[0] <= distances[1] and distances[0] <= distances[2]:
        return left
    if distances[1] <= distances[2]:
        return above
    return corner


def decode_png(data: bytes) -> dict[str, Any]:
    """Decode an 8-bit, non-interlaced PNG into rows of ints or tuples."""
    if not data.startswith(PNG_SIGNATURE):
        raise VisionError("not a PNG file")
    position = len(PNG_SIGNATURE)
    header: tuple[int, int, int, int] | None = None
    compressed = bytearray()
    while position + 8 <= len(data):
        length = struct.unpack(">I", data[position : position + 4])[0]
        kind = data[position + 4 : position + 8]
        payload = data[position + 8 : position + 8 + length]
        position += 12 + length
        if kind == b"IHDR":
            width, height, depth, colour, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if depth != 8 or interlace != 0 or compression != 0 or filtering != 0:
                raise VisionError("only 8-bit non-interlaced PNGs are supported")
            if colour not in (0, 2, 4, 6):
                raise VisionError(f"colour type {colour} is not supported")
            header = (width, height, colour, 0)
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            break
    if header is None:
        raise VisionError("the PNG has no header")
    width, height, colour, _ = header
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[colour]
    raw = zlib.decompress(bytes(compressed))
    stride = width * channels
    rows: list[list[Any]] = []
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        offset += 1
        line = bytearray(raw[offset : offset + stride])
        offset += stride
        for index in range(stride):
            left = line[index - channels] if index >= channels else 0
            above = previous[index]
            corner = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                value = line[index]
            elif filter_type == 1:
                value = line[index] + left
            elif filter_type == 2:
                value = line[index] + above
            elif filter_type == 3:
                value = line[index] + ((left + above) >> 1)
            elif filter_type == 4:
                value = line[index] + _paeth(left, above, corner)
            else:
                raise VisionError(f"unknown scanline filter {filter_type}")
            line[index] = value & 0xFF
        previous = line
        if channels == 1:
            rows.append(list(line))
        elif channels == 3:
            rows.append([tuple(line[index : index + 3]) for index in range(0, stride, 3)])
        elif channels == 4:
            rows.append([tuple(line[index : index + 4]) for index in range(0, stride, 4)])
        else:
            rows.append([(line[index], line[index + 1]) for index in range(0, stride, 2)])
    return {"width": width, "height": height, "colour_type": colour, "rows": rows}


def to_gray(rows: Sequence[Sequence[Any]]) -> list[list[int]]:
    result = []
    for row in rows:
        converted = []
        for pixel in row:
            if isinstance(pixel, int):
                converted.append(pixel)
            else:
                red, green, blue = pixel[0], pixel[1], pixel[2]
                converted.append(int(0.299 * red + 0.587 * green + 0.114 * blue))
        result.append(converted)
    return result


def box_blur(gray: Sequence[Sequence[int]], radius: int = 1) -> list[list[int]]:
    if radius < 1:
        raise VisionError("radius must be at least 1")
    height, width = len(gray), len(gray[0])
    window = 2 * radius + 1
    horizontal = [[0] * width for _ in range(height)]
    for y in range(height):
        running = 0
        for x in range(-radius, radius + 1):
            running += gray[y][min(max(x, 0), width - 1)]
        for x in range(width):
            horizontal[y][x] = running // window
            leaving = gray[y][min(max(x - radius, 0), width - 1)]
            entering = gray[y][min(max(x + radius + 1, 0), width - 1)]
            running += entering - leaving
    blurred = [[0] * width for _ in range(height)]
    for x in range(width):
        running = 0
        for y in range(-radius, radius + 1):
            running += horizontal[min(max(y, 0), height - 1)][x]
        for y in range(height):
            blurred[y][x] = running // window
            leaving = horizontal[min(max(y - radius, 0), height - 1)][x]
            entering = horizontal[min(max(y + radius + 1, 0), height - 1)][x]
            running += entering - leaving
    return blurred


def sobel_edges(gray: Sequence[Sequence[int]]) -> list[list[int]]:
    height, width = len(gray), len(gray[0])

    def at(x: int, y: int) -> int:
        return gray[min(max(y, 0), height - 1)][min(max(x, 0), width - 1)]

    edges = [[0] * width for _ in range(height)]
    for y in range(height):
        for x in range(width):
            gx = (
                -at(x - 1, y - 1)
                - 2 * at(x - 1, y)
                - at(x - 1, y + 1)
                + at(x + 1, y - 1)
                + 2 * at(x + 1, y)
                + at(x + 1, y + 1)
            )
            gy = (
                -at(x - 1, y - 1)
                - 2 * at(x, y - 1)
                - at(x + 1, y - 1)
                + at(x - 1, y + 1)
                + 2 * at(x, y + 1)
                + at(x + 1, y + 1)
            )
            edges[y][x] = min(255, int(math.hypot(gx, gy)))
    return edges


def threshold(gray: Sequence[Sequence[int]], value: int) -> list[list[int]]:
    return [[255 if pixel >= value else 0 for pixel in row] for row in gray]


def connected_components(binary: Sequence[Sequence[int]]) -> list[dict[str, Any]]:
    """Perceptual binding: pixels that touch become one object."""
    height, width = len(binary), len(binary[0])
    seen = [[False] * width for _ in range(height)]
    components = []
    for start_y in range(height):
        for start_x in range(width):
            if binary[start_y][start_x] == 0 or seen[start_y][start_x]:
                continue
            stack = [(start_x, start_y)]
            seen[start_y][start_x] = True
            pixels = []
            while stack:
                x, y = stack.pop()
                pixels.append((x, y))
                for nx, ny in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
                    if (
                        0 <= nx < width
                        and 0 <= ny < height
                        and not seen[ny][nx]
                        and binary[ny][nx]
                    ):
                        seen[ny][nx] = True
                        stack.append((nx, ny))
            xs = [p[0] for p in pixels]
            ys = [p[1] for p in pixels]
            components.append(
                {
                    "area": len(pixels),
                    "box": (min(xs), min(ys), max(xs), max(ys)),
                    "centre": (
                        round(sum(xs) / len(xs), 2),
                        round(sum(ys) / len(ys), 2),
                    ),
                }
            )
    components.sort(key=lambda item: -item["area"])
    return components


def saliency(gray: Sequence[Sequence[int]]) -> list[list[float]]:
    """Center-surround difference: what stands out from its neighbourhood."""
    fine = box_blur(gray, 1)
    coarse = box_blur(gray, 3)
    differences = [
        [abs(fine[y][x] - coarse[y][x]) for x in range(len(gray[0]))]
        for y in range(len(gray))
    ]
    peak = max(max(row) for row in differences) or 1
    return [[round(value / peak, 4) for value in row] for row in differences]


def template_match(
    gray: Sequence[Sequence[int]], template: Sequence[Sequence[int]]
) -> dict[str, Any]:
    """Normalised cross-correlation; returns the best position and its score."""
    height, width = len(gray), len(gray[0])
    t_height, t_width = len(template), len(template[0])
    if t_height > height or t_width > width:
        raise VisionError("the template is larger than the image")
    t_mean = sum(sum(row) for row in template) / (t_height * t_width)
    t_centred = [[value - t_mean for value in row] for row in template]
    t_norm = math.sqrt(sum(value * value for row in t_centred for value in row)) or 1e-9
    best = {"score": -2.0, "x": 0, "y": 0}
    for y in range(height - t_height + 1):
        for x in range(width - t_width + 1):
            window = [
                [gray[y + dy][x + dx] for dx in range(t_width)] for dy in range(t_height)
            ]
            w_mean = sum(sum(row) for row in window) / (t_height * t_width)
            numerator = sum(
                (window[dy][dx] - w_mean) * t_centred[dy][dx]
                for dy in range(t_height)
                for dx in range(t_width)
            )
            w_norm = (
                math.sqrt(
                    sum(
                        (window[dy][dx] - w_mean) ** 2
                        for dy in range(t_height)
                        for dx in range(t_width)
                    )
                )
                or 1e-9
            )
            score = numerator / (w_norm * t_norm)
            if score > best["score"]:
                best = {"score": round(score, 4), "x": x, "y": y}
    return best


def frame_difference(frames: Sequence[Sequence[Sequence[int]]]) -> list[list[int]]:
    if len(frames) < 2:
        raise VisionError("at least two frames are needed")
    height, width = len(frames[0]), len(frames[0][0])
    motion = [[0] * width for _ in range(height)]
    for previous, current in pairwise(frames):
        for y in range(height):
            for x in range(width):
                motion[y][x] = max(motion[y][x], abs(current[y][x] - previous[y][x]))
    return motion


def softmax_attention(features: Sequence[float]) -> dict[str, Any]:
    if not features:
        raise VisionError("attention needs features")
    peak = max(features)
    exponentials = [math.exp(value - peak) for value in features]
    total = sum(exponentials)
    weights = [round(value / total, 4) for value in exponentials]
    return {
        "weights": weights,
        "context": round(sum(w * f for w, f in zip(weights, features)), 4),
        "entropy": round(
            -sum(w * math.log(w) for w in weights if w > 0) / math.log(len(weights))
            if len(weights) > 1
            else 0.0,
            4,
        ),
    }


def fuse_modalities(modalities: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Weighted fusion with an agreement score across modalities."""
    if not modalities:
        raise VisionError("nothing to fuse")
    total = sum(float(item.get("confidence", 1.0)) for item in modalities) or 1e-9
    fused = sum(
        float(item["value"]) * float(item.get("confidence", 1.0)) for item in modalities
    ) / total
    spread = max(abs(float(item["value"]) - fused) for item in modalities)
    agreement = round(max(0.0, 1.0 - spread), 4)
    return {
        "value": round(fused, 4),
        "confidence": round(total / len(modalities), 4),
        "agreement": agreement,
        "disagree": agreement < 0.6,
    }


def habituate(response: float, repetitions: int, *, rate: float = 0.2) -> dict[str, Any]:
    if repetitions < 0:
        raise VisionError("repetitions cannot be negative")
    remaining = response * ((1.0 - rate) ** repetitions)
    return {
        "response": round(remaining, 4),
        "drop": round(response - remaining, 4),
        "habituated": remaining < 0.5 * response,
    }


def adapt(level: float, stimulus: float, *, rate: float = 0.3) -> dict[str, Any]:
    updated = level + rate * (stimulus - level)
    return {
        "level": round(updated, 4),
        "delta": round(updated - level, 4),
        "sensitivity": round(1.0 / (1.0 + abs(updated)), 4),
    }


def read_wav(path: str) -> dict[str, Any]:
    with wave.open(path, "rb") as handle:
        channels = handle.getnchannels()
        width = handle.getsampwidth()
        rate = handle.getframerate()
        frames = handle.getnframes()
        raw = handle.readframes(frames)
    if width != 2:
        raise VisionError("only 16-bit PCM is supported")
    samples = list(struct.unpack("<" + "h" * (len(raw) // 2), raw))
    if channels > 1:
        samples = samples[::channels]
    return {
        "rate": rate,
        "channels": channels,
        "samples": samples,
        "duration_s": round(len(samples) / rate, 4),
        "peak": max((abs(value) for value in samples), default=0),
    }


def spectrum(samples: Sequence[float]) -> list[complex]:
    """Radix-2 FFT, zero-padded to a power of two."""
    size = 1
    while size < len(samples):
        size *= 2
    data = [complex(value) for value in samples] + [0j] * (size - len(samples))
    j = 0
    for index in range(1, size):
        bit = size >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if index < j:
            data[index], data[j] = data[j], data[index]
    step = 2
    while step <= size:
        half = step // 2
        twiddle = [complex(math.cos(-2 * math.pi * k / step), math.sin(-2 * math.pi * k / step)) for k in range(half)]
        for start in range(0, size, step):
            for k in range(half):
                left = data[start + k]
                right = data[start + k + half] * twiddle[k]
                data[start + k] = left + right
                data[start + k + half] = left - right
        step *= 2
    return data


def dominant_frequency(samples: Sequence[float], rate: int) -> dict[str, Any]:
    if not samples:
        raise VisionError("no samples")
    transformed = spectrum(samples)
    limit = len(transformed) // 2
    magnitudes = [abs(transformed[index]) for index in range(1, limit)]
    if not magnitudes:
        raise VisionError("the signal is too short")
    peak = max(range(len(magnitudes)), key=lambda index: magnitudes[index]) + 1
    return {
        "hz": round(peak * rate / len(transformed), 2),
        "magnitude": round(magnitudes[peak - 1], 2),
        "bins": limit,
    }
