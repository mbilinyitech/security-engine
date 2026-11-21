"""Keep the CPU cool by measuring it, not by hoping.

The governor reads /proc/stat and the thermal zones, then enforces a duty cycle:
work for a slice, sleep for the rest. Above the temperature ceiling it sleeps
longer. It cannot promise a temperature, only a measured duty cycle.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class ThermalError(Exception):
    pass


def cpu_times() -> dict[str, int]:
    line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
    parts = [int(value) for value in line.split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return {"total": sum(parts), "idle": idle}


def cpu_usage(interval_s: float = 0.05) -> float:
    if interval_s < 0:
        raise ThermalError("the interval cannot be negative")
    first = cpu_times()
    time.sleep(interval_s)
    second = cpu_times()
    total = second["total"] - first["total"]
    idle = second["idle"] - first["idle"]
    if total <= 0:
        return 0.0
    return round(max(0.0, min(1.0, 1.0 - idle / total)), 3)


def temperature() -> float | None:
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            raw = (zone / "temp").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        value = float(raw) / 1000.0
        if -20 < value < 150:
            return round(value, 1)
    return None


def duty_cycle(usage: float, *, target: float = 0.7) -> float:
    """Fraction of wall time that may be spent working."""
    if not 0 <= usage <= 1:
        raise ThermalError("usage lives between 0 and 1")
    if not 0 < target <= 1:
        raise ThermalError("the target lives in (0, 1]")
    if usage <= target:
        return 1.0
    return round(max(0.1, target / usage), 3)


class Governor:
    def __init__(self, *, target: float = 0.7, max_temp: float = 78.0, slice_s: float = 0.02) -> None:
        if not 0 < target <= 1:
            raise ThermalError("the target lives in (0, 1]")
        if max_temp <= 0 or slice_s <= 0:
            raise ThermalError("the ceiling and the slice must be positive")
        self.target = target
        self.max_temp = max_temp
        self.slice_s = slice_s

    def state(self) -> dict[str, Any]:
        usage = cpu_usage(self.slice_s)
        heat = temperature()
        level = "cool"
        if heat is not None and heat >= self.max_temp:
            level = "hot"
        elif usage > self.target:
            level = "warm"
        return {
            "usage": usage,
            "temperature_c": heat,
            "level": level,
            "target": self.target,
            "max_temp_c": self.max_temp,
            "duty": duty_cycle(usage, target=self.target),
        }

    def pause(self) -> float:
        state = self.state()
        if state["level"] == "hot":
            return round(self.slice_s * 10, 3)
        if state["level"] == "warm":
            return round(self.slice_s * 4, 3)
        return 0.0

    def run(self, steps: int, work: Callable[[int], Any]) -> dict[str, Any]:
        if steps < 1:
            raise ThermalError("at least one step is required")
        started = time.perf_counter()
        pauses = 0.0
        results = []
        for index in range(steps):
            results.append(work(index))
            delay = self.pause()
            if delay:
                pauses += delay
                time.sleep(delay)
        elapsed = time.perf_counter() - started
        return {
            "steps": steps,
            "elapsed_s": round(elapsed, 3),
            "paused_s": round(pauses, 3),
            "state": self.state(),
            "results": results,
        }
