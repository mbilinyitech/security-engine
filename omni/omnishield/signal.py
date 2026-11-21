"""Collect, synthesise and clean waveforms fast, on the CPU.

The pipeline is explicit and timed: DC removal, median despiking, smoothing, a
one-pole low-pass and peak normalisation. Signal-to-noise ratio is measured
before and after, so a clean that makes things worse is visible.
"""

from __future__ import annotations

import math
import os
import struct
import time
import wave
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .stealth import XorShift64
from .vision import dominant_frequency, spectrum


class SignalError(Exception):
    pass


def synthesise(
    frequencies: Sequence[float], seconds: float, *, rate: int = 8000, amplitude: float = 0.5
) -> list[float]:
    if not frequencies:
        raise SignalError("at least one frequency is required")
    if seconds <= 0 or rate <= 0:
        raise SignalError("seconds and rate must be positive")
    if not 0 < amplitude <= 1:
        raise SignalError("the amplitude lives in (0, 1]")
    count = int(seconds * rate)
    scale = amplitude / len(frequencies)
    return [
        sum(scale * math.sin(2 * math.pi * frequency * index / rate) for frequency in frequencies)
        for index in range(count)
    ]


def add_noise(samples: Sequence[float], *, amplitude: float = 0.1, seed: int = 1) -> list[float]:
    if not 0 <= amplitude <= 1:
        raise SignalError("noise amplitude lives between 0 and 1")
    generator = XorShift64(seed)
    noisy = []
    for sample in samples:
        unit = (generator.next_u64() % 20001) / 10000.0 - 1.0
        noisy.append(max(-1.0, min(1.0, sample + amplitude * unit)))
    return noisy


def write_wav(path: str | os.PathLike[str], samples: Sequence[float], *, rate: int = 8000) -> Path:
    if not samples:
        raise SignalError("there is nothing to write")
    if rate <= 0:
        raise SignalError("the rate must be positive")
    frames = bytearray()
    for sample in samples:
        frames.extend(struct.pack("<h", int(max(-1.0, min(1.0, sample)) * 32767)))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(target), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(bytes(frames))
    return target


def resample(samples: Sequence[float], src_rate: int, dst_rate: int) -> list[float]:
    if src_rate <= 0 or dst_rate <= 0:
        raise SignalError("rates must be positive")
    if src_rate == dst_rate:
        return list(samples)
    count = max(1, round(len(samples) * dst_rate / src_rate))
    ratio = src_rate / dst_rate
    output = []
    for index in range(count):
        position = index * ratio
        left = int(position)
        right = min(left + 1, len(samples) - 1)
        fraction = position - left
        output.append(samples[left] * (1 - fraction) + samples[right] * fraction)
    return output


def remove_dc(samples: Sequence[float]) -> list[float]:
    if not samples:
        raise SignalError("the signal is empty")
    average = sum(samples) / len(samples)
    return [sample - average for sample in samples]


def moving_average(samples: Sequence[float], window: int = 5) -> list[float]:
    if window < 1:
        raise SignalError("the window must be positive")
    if window == 1:
        return list(samples)
    half = window // 2
    output = []
    for index in range(len(samples)):
        low = max(0, index - half)
        high = min(len(samples), index + half + 1)
        output.append(sum(samples[low:high]) / (high - low))
    return output


def median_filter(samples: Sequence[float], window: int = 3) -> list[float]:
    if window < 3 or window % 2 == 0:
        raise SignalError("the window must be odd and at least three")
    half = window // 2
    output = []
    for index in range(len(samples)):
        low = max(0, index - half)
        high = min(len(samples), index + half + 1)
        chunk = sorted(samples[low:high])
        output.append(chunk[len(chunk) // 2])
    return output


def one_pole_lowpass(samples: Sequence[float], *, alpha: float = 0.2) -> list[float]:
    if not 0 < alpha <= 1:
        raise SignalError("alpha lives in (0, 1]")
    output = []
    previous = samples[0] if samples else 0.0
    for sample in samples:
        previous = previous + alpha * (sample - previous)
        output.append(previous)
    return output


def one_pole_highpass(samples: Sequence[float], *, alpha: float = 0.05) -> list[float]:
    if not 0 < alpha <= 1:
        raise SignalError("alpha lives in (0, 1]")
    low = one_pole_lowpass(samples, alpha=alpha)
    return [sample - baseline for sample, baseline in zip(samples, low, strict=True)]


def normalise(samples: Sequence[float], *, peak: float = 0.9) -> list[float]:
    if not samples:
        raise SignalError("the signal is empty")
    if not 0 < peak <= 1:
        raise SignalError("the peak lives in (0, 1]")
    largest = max(abs(sample) for sample in samples) or 1.0
    return [sample * peak / largest for sample in samples]


def detect_peaks(samples: Sequence[float], *, threshold: float = 0.5, min_distance: int = 5) -> list[dict[str, Any]]:
    if min_distance < 1:
        raise SignalError("the distance must be positive")
    peaks = []
    last = -min_distance
    for index in range(1, len(samples) - 1):
        value = abs(samples[index])
        if value < threshold:
            continue
        if value >= abs(samples[index - 1]) and value >= abs(samples[index + 1]) and index - last >= min_distance:
            peaks.append({"index": index, "value": round(samples[index], 4)})
            last = index
    return peaks


def scale_match(reference: Sequence[float], test: Sequence[float]) -> tuple[list[float], float]:
    """Remove a pure gain difference before comparing two signals."""
    if len(reference) != len(test) or not reference:
        raise SignalError("reference and test must be the same non-zero length")
    denominator = sum(value * value for value in test) or 1e-12
    gain = sum(r * t for r, t in zip(reference, test, strict=True)) / denominator
    return [value * gain for value in test], round(gain, 4)


def snr_db(reference: Sequence[float], test: Sequence[float]) -> float:
    if len(reference) != len(test) or not reference:
        raise SignalError("reference and test must be the same non-zero length")
    signal_power = sum(value * value for value in reference) / len(reference)
    noise_power = sum((a - b) ** 2 for a, b in zip(reference, test, strict=True)) / len(reference)
    if noise_power == 0:
        return 99.0
    return round(10 * math.log10(max(signal_power, 1e-12) / noise_power), 3)


def spectrogram(
    samples: Sequence[float], *, rate: int = 8000, window: int = 256, hop: int = 128
) -> dict[str, Any]:
    if len(samples) < window:
        raise SignalError("the signal is shorter than one window")
    if hop < 1:
        raise SignalError("the hop must be positive")
    frames = []
    for start in range(0, len(samples) - window + 1, hop):
        chunk = list(samples[start : start + window])
        magnitude = [abs(value) for value in spectrum(chunk)[: window // 2]]
        frames.append([round(20 * math.log10(value + 1e-9), 2) for value in magnitude])
    return {
        "frames": frames,
        "frequencies": [round(index * rate / window, 2) for index in range(window // 2)],
        "window": window,
        "hop": hop,
    }


def collect(chunks: Iterable[Sequence[float]]) -> list[float]:
    samples: list[float] = []
    for chunk in chunks:
        samples.extend(chunk)
    if not samples:
        raise SignalError("no samples were collected")
    return samples


def throughput(samples: Sequence[float], elapsed_ms: float) -> float:
    if elapsed_ms <= 0:
        raise SignalError("the elapsed time must be positive")
    return round(len(samples) / (elapsed_ms / 1000), 1)


def clean(
    samples: Sequence[float], *, rate: int = 8000, reference: Sequence[float] | None = None
) -> dict[str, Any]:
    if len(samples) < 8:
        raise SignalError("the signal is too short to clean")
    started = time.perf_counter()
    stages = []

    def stage(name: str, operation: Any) -> list[float]:
        mark = time.perf_counter()
        result = operation()
        stages.append({"stage": name, "ms": round((time.perf_counter() - mark) * 1000, 3)})
        return result

    working = stage("remove_dc", lambda: remove_dc(samples))
    working = stage("despike", lambda: median_filter(working, 3))
    working = stage("smooth", lambda: moving_average(working, 3))
    working = stage("lowpass", lambda: one_pole_lowpass(working, alpha=0.8))
    working = stage("normalise", lambda: normalise(working))
    elapsed = (time.perf_counter() - started) * 1000
    document: dict[str, Any] = {
        "samples": working,
        "count": len(working),
        "stages": stages,
        "elapsed_ms": round(elapsed, 3),
        "samples_per_second": throughput(working, elapsed),
        "rate": rate,
        "peak_hz": dominant_frequency(working, rate)["hz"],
    }
    if reference is not None:
        if len(reference) != len(working):
            raise SignalError("the reference must be the same length as the signal")
        before = snr_db(reference, samples)
        matched, gain = scale_match(reference, working)
        after = snr_db(reference, matched)
        document["gain"] = gain
        document["snr_before_db"] = before
        document["snr_after_db"] = after
        document["improvement_db"] = round(after - before, 3)
    return document
