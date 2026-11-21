"""3D on the CPU: a Rust ray tracer, a Python painter's renderer, a simulator.

The Rust path traces primary rays against spheres, a triangle cube and a ground
plane, with jittered soft shadows and tone mapping. The Python path projects the
same objects with a perspective camera and sorts faces by depth, which is enough
for orbit frames and for machines without the Rust binary.
"""

from __future__ import annotations

import math
import os
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .render import Canvas, RenderError, read_ppm

Vec3 = tuple[float, float, float]


def _add(a: Vec3, b: Vec3) -> Vec3:
    return (a[0] + b[0], a[1] + b[1], a[2] + b[2])


def _sub(a: Vec3, b: Vec3) -> Vec3:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def _mul(a: Vec3, k: float) -> Vec3:
    return (a[0] * k, a[1] * k, a[2] * k)


def _dot(a: Vec3, b: Vec3) -> float:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _length(a: Vec3) -> float:
    return math.sqrt(_dot(a, a))


def _normalise(a: Vec3) -> Vec3:
    length = _length(a) or 1e-12
    return _mul(a, 1.0 / length)


def _cross(a: Vec3, b: Vec3) -> Vec3:
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _binary() -> Path:
    return Path(__file__).resolve().parent.parent / "organism" / "target" / "release" / "organism"


PRESETS = {
    "draft": (320, 200, 1, 4),
    "standard": (480, 300, 2, 4),
    "high": (800, 500, 3, 8),
}


def scene3d(
    width: int = 320,
    height: int = 200,
    *,
    samples: int = 2,
    engine: str = "auto",
    threads: int = 4,
    angle: float = 0.0,
    aperture: float = 0.0,
) -> dict[str, Any]:
    """Trace the fixed scene with Rust, or paint it with Python."""
    if engine not in {"auto", "rust", "python"}:
        raise RenderError("engine is auto, rust or python")
    if width < 8 or height < 8:
        raise RenderError("the frame is too small")
    if samples < 1:
        raise RenderError("at least one sample is required")
    if engine in {"auto", "rust"}:
        binary = _binary()
        if binary.is_file() and os.access(binary, os.X_OK):
            import json

            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "scene3d.ppm"
                completed = subprocess.run(
                    [
                        str(binary),
                        "render3d",
                        str(width),
                        str(height),
                        str(samples),
                        str(target),
                        str(threads),
                        str(angle),
                        str(aperture),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                )
                if completed.returncode != 0:
                    raise RenderError(f"the Rust ray tracer failed: {completed.stderr.strip()}")
                document = json.loads(completed.stdout)
                parsed_width, parsed_height, rows = read_ppm(target.read_bytes())
            canvas = Canvas(parsed_width, parsed_height)
            for y, row in enumerate(rows):
                for x, pixel in enumerate(row):
                    canvas.set(x, y, pixel)
            return {
                "canvas": canvas,
                "engine": "rust",
                "samples": samples,
                "threads": document.get("threads", threads),
                "angle": angle,
                "aperture": aperture,
                "elapsed_ms": document["elapsed_ms"],
                "rays": document["rays"],
                "rays_per_second": document["rays_per_second"],
            }
        if engine == "rust":
            raise RenderError("the Rust binary is not built")
    return paint3d(width, height, angle=angle or 0.35)


def _project(point: Vec3, angle: float, width: int, height: int) -> tuple[float, float, float] | None:
    """Rotate around Y, then apply a simple perspective divide."""
    cos_a, sin_a = math.cos(angle), math.sin(angle)
    x = point[0] * cos_a - point[2] * sin_a
    z = point[0] * sin_a + point[2] * cos_a
    depth = z + 4.2
    if depth <= 0.2:
        return None
    scale = 1.9 * width / depth
    return (width / 2 + x * scale, height * 0.62 - point[1] * scale, depth)


def paint3d(width: int = 320, height: int = 200, *, angle: float = 0.35) -> dict[str, Any]:
    """Painter's algorithm: faces sorted by depth, flat shading, ground grid."""
    canvas = Canvas(width, height)
    for y in range(height):
        ratio = y / max(1, height - 1)
        canvas.fill_rect(
            0,
            y,
            width,
            1,
            (
                round(92 + (222 - 92) * ratio),
                round(140 + (232 - 140) * ratio),
                round(205 + (244 - 205) * ratio),
            ),
        )
    light = _normalise((-0.4, 0.8, 0.5))
    faces: list[tuple[float, list[tuple[float, float]], tuple[int, int, int]]] = []

    def add_face(points: Sequence[Vec3], colour: tuple[int, int, int]) -> None:
        projected = [_project(point, angle, width, height) for point in points]
        if any(point is None for point in projected):
            return
        screen = [(point[0], point[1]) for point in projected if point is not None]
        depth = sum(point[2] for point in projected if point is not None) / len(screen)
        normal = _normalise(_cross(_sub(points[1], points[0]), _sub(points[2], points[0])))
        shade = 0.45 + 0.55 * max(0.0, _dot(normal, light))
        faces.append(
            (
                depth,
                screen,
                (round(colour[0] * shade), round(colour[1] * shade), round(colour[2] * shade)),
            )
        )

    half = 0.55
    corners = [
        (-half, 0.0, -half), (half, 0.0, -half), (half, 0.0, half), (-half, 0.0, half),
        (-half, 2 * half, -half), (half, 2 * half, -half), (half, 2 * half, half), (-half, 2 * half, half),
    ]
    for face in (
        (0, 1, 2), (0, 2, 3), (4, 6, 5), (4, 7, 6), (0, 4, 5), (0, 5, 1),
        (1, 5, 6), (1, 6, 2), (2, 6, 7), (2, 7, 3), (3, 7, 4), (3, 4, 0),
    ):
        add_face([corners[face[0]], corners[face[1]], corners[face[2]]], (196, 84, 66))

    for depth, screen, colour in sorted(faces, key=lambda entry: -entry[0]):
        canvas.polygon([(round(x), round(y)) for x, y in screen], colour)
    for centre, radius, colour in (
        ((-0.75, 0.55, 0.1), 0.55, (62, 138, 226)),
        ((0.55, 0.3, 0.75), 0.3, (232, 192, 72)),
    ):
        projected = _project(centre, angle, width, height)
        if projected is None:
            continue
        x, y, depth = projected
        canvas.circle(round(x), round(y), max(2, round(radius * 1.9 * width / depth)), colour)
    for step in range(-3, 4):
        start = _project((step * 0.6, 0.0, -3.0), angle, width, height)
        end = _project((step * 0.6, 0.0, 3.0), angle, width, height)
        if start and end:
            canvas.line(round(start[0]), round(start[1]), round(end[0]), round(end[1]), (120, 132, 150))
        start = _project((-3.0, 0.0, step * 0.6), angle, width, height)
        end = _project((3.0, 0.0, step * 0.6), angle, width, height)
        if start and end:
            canvas.line(round(start[0]), round(start[1]), round(end[0]), round(end[1]), (120, 132, 150))
    return {"canvas": canvas, "engine": "python", "samples": 1, "angle": angle}


def orbit(frames: int = 12, width: int = 240, height: int = 150) -> list[Canvas]:
    if frames < 2:
        raise RenderError("an orbit needs at least two frames")
    return [
        paint3d(width, height, angle=index * 2 * math.pi / frames)["canvas"]
        for index in range(frames)
    ]


def plot3d(
    points: Sequence[Vec3],
    *,
    width: int = 480,
    height: int = 320,
    title: str = "3D points",
) -> Canvas:
    if not points:
        raise RenderError("no points to plot")
    canvas = Canvas(width, height)
    canvas.gradient((16, 22, 40), (36, 46, 70))
    canvas.text(14, 10, title[: (width - 30) // 6], (240, 245, 250))
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    zs = [point[2] for point in points]
    span = max(max(xs) - min(xs), max(ys) - min(ys), max(zs) - min(zs), 1e-6)
    angle = 0.7
    projected = []
    for x, y, z in points:
        nx = (x - (max(xs) + min(xs)) / 2) / span
        ny = (y - (max(ys) + min(ys)) / 2) / span
        nz = (z - (max(zs) + min(zs)) / 2) / span
        rotated_x = nx * math.cos(angle) - nz * math.sin(angle)
        rotated_z = nx * math.sin(angle) + nz * math.cos(angle)
        depth = rotated_z + 2.0
        screen_x = width / 2 + rotated_x * width * 0.55 / depth
        screen_y = height * 0.58 - (ny - 0.35 * rotated_z) * height * 0.75 / depth
        projected.append((depth, screen_x, screen_y, y))
    projected.sort(key=lambda entry: -entry[0])
    for depth, screen_x, screen_y, value in projected:
        size = max(1, min(5, round(4 / depth)))
        shade = max(0, min(255, round(120 + 135 * value / span)))
        canvas.circle(round(screen_x), round(screen_y), size, (shade, 180, 255 - shade))
    canvas.text(14, height - 18, f"{len(points)} POINTS", (200, 210, 225))
    return canvas


def simulate_projectile(
    speed: float = 12.0, angle_degrees: float = 45.0, *, dt: float = 0.02, steps: int = 400, drag: float = 0.02
) -> dict[str, Any]:
    if speed <= 0 or steps < 2 or dt <= 0:
        raise RenderError("speed, steps and dt must be positive")
    angle = math.radians(angle_degrees)
    position = [0.0, 0.0]
    velocity = [speed * math.cos(angle), speed * math.sin(angle)]
    rows = []
    apex = 0.0
    for step in range(steps):
        speed_now = math.hypot(velocity[0], velocity[1])
        acceleration = [-drag * speed_now * velocity[0], -9.81 - drag * speed_now * velocity[1]]
        velocity = [velocity[0] + acceleration[0] * dt, velocity[1] + acceleration[1] * dt]
        position = [position[0] + velocity[0] * dt, position[1] + velocity[1] * dt]
        if position[1] < 0:
            break
        apex = max(apex, position[1])
        energy = 0.5 * (velocity[0] ** 2 + velocity[1] ** 2) + 9.81 * position[1]
        rows.append({"t": round(step * dt, 4), "x": round(position[0], 4), "y": round(position[1], 4), "energy": round(energy, 4)})
    return {
        "rows": rows,
        "range": rows[-1]["x"] if rows else 0.0,
        "apex": round(apex, 3),
        "flight_s": rows[-1]["t"] if rows else 0.0,
        "energy_change": round(max(row["energy"] for row in rows) - min(row["energy"] for row in rows), 4),
        "model": "RK1 with quadratic drag",
    }


def simulate_pendulum(
    length: float = 1.0, theta0_degrees: float = 30.0, *, dt: float = 0.005, steps: int = 2000, damping: float = 0.0
) -> dict[str, Any]:
    if length <= 0 or steps < 10 or dt <= 0:
        raise RenderError("length, steps and dt must be positive")
    theta = math.radians(theta0_degrees)
    omega = 0.0
    rows = []
    energy0 = None
    for step in range(steps):
        acceleration = -(9.81 / length) * math.sin(theta) - damping * omega
        omega += acceleration * dt
        theta += omega * dt
        energy = 0.5 * (length * omega) ** 2 + 9.81 * length * (1 - math.cos(theta))
        energy0 = energy if energy0 is None else energy0
        rows.append({"t": round(step * dt, 4), "theta": round(theta, 4), "omega": round(omega, 4), "energy": round(energy, 4)})
    crossings = [
        rows[index]["t"]
        for index in range(1, len(rows))
        if rows[index - 1]["theta"] <= 0 < rows[index]["theta"]
    ]
    period = (crossings[-1] - crossings[0]) / (len(crossings) - 1) if len(crossings) > 1 else None
    return {
        "rows": rows,
        "period_s": round(period, 4) if period else None,
        "energy_drift": round(abs(rows[-1]["energy"] - energy0), 6),
        "model": "RK1 pendulum",
    }


def preset(name: str) -> dict[str, Any]:
    if name not in PRESETS:
        raise RenderError(f"unknown preset {name}; choose from {sorted(PRESETS)}")
    width, height, samples, threads = PRESETS[name]
    return {"name": name, "width": width, "height": height, "samples": samples, "threads": threads}


def video(
    frames: int = 24,
    *,
    preset_name: str = "draft",
    aperture: float = 0.02,
    engine: str = "auto",
) -> dict[str, Any]:
    """Render an orbiting sequence with the Rust tracer, then encode it as GIF."""
    import time as clock

    from .render import save_gif

    settings = preset(preset_name)
    if frames < 2:
        raise RenderError("a video needs at least two frames")
    started = clock.perf_counter()
    canvases = []
    timings = []
    for index in range(frames):
        angle = index * 2 * math.pi / frames
        rendered = scene3d(
            settings["width"],
            settings["height"],
            samples=settings["samples"],
            engine=engine,
            threads=settings["threads"],
            angle=angle,
            aperture=aperture,
        )
        timings.append(rendered["elapsed_ms"])
        canvases.append(rendered["canvas"])
    encode_started = clock.perf_counter()
    path = save_gif(canvases, Path("orbit.gif"), delay_cs=8)
    encode_ms = round((clock.perf_counter() - encode_started) * 1000, 3)
    return {
        "frames": frames,
        "preset": settings,
        "frame_ms": timings,
        "mean_frame_ms": round(sum(timings) / len(timings), 2),
        "min_frame_ms": min(timings),
        "encode_ms": encode_ms,
        "total_ms": round((clock.perf_counter() - started) * 1000, 2),
        "canvas": canvases,
        "gif": path,
    }


def pathtrace(
    scene_path: str | os.PathLike[str],
    out_path: str | os.PathLike[str],
    *,
    binary: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Render a JSON scene with the Rust path tracer and save it as PNG."""
    import json
    import subprocess

    executable = Path(binary) if binary else _binary()
    if not (executable.is_file() and os.access(executable, os.X_OK)):
        raise RenderError("the Rust binary is not built; run cargo build --release")
    source = Path(scene_path)
    if not source.is_file():
        raise RenderError(f"no scene at {source}")
    try:
        json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RenderError(f"the scene is not valid JSON: {error}") from error
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "scene.ppm"
        completed = subprocess.run(
            [str(executable), "pathtrace", str(source), str(target)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            raise RenderError(f"the path tracer failed: {completed.stderr.strip()}")
        document = json.loads(completed.stdout)
        width, height, rows = read_ppm(target.read_bytes())
    canvas = Canvas(width, height)
    for y, row in enumerate(rows):
        for x, pixel in enumerate(row):
            canvas.set(x, y, pixel)
    saved = canvas.save_png(out_path)
    return {**document, "png": str(saved), "png_bytes": saved.stat().st_size, "scene": str(source)}
