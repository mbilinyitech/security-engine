"""Hear and speak, with the maths shown.

Recognition is a keyword spotter: MFCCs compared with stored templates using
dynamic time warping. It is not a general recogniser and it knows only the words
it was trained on.

Speaking is formant synthesis: vowels from three resonances, consonants from
short noise bursts. It is intelligible-ish and robotic, never a natural voice.
"""

from __future__ import annotations

import math
import os
import time
from collections.abc import Sequence
from typing import Any

from .signal import normalise, write_wav
from .vision import read_wav, spectrum

RATE = 8000
FRAME = 0.025
HOP = 0.010
N_MELS = 26
N_MFCC = 13

VOWELS = {
    "a": (730.0, 1090.0, 2440.0),
    "e": (530.0, 1840.0, 2480.0),
    "i": (270.0, 2290.0, 3010.0),
    "o": (570.0, 840.0, 2410.0),
    "u": (300.0, 870.0, 2240.0),
}
NOISE = {"k", "p", "t", "s", "h", "c", "f"}


class SpeechError(Exception):
    pass


def _frames(samples: Sequence[float], rate: int) -> list[list[float]]:
    size = max(8, int(FRAME * rate))
    hop = max(1, int(HOP * rate))
    frames = []
    for start in range(0, max(1, len(samples) - size + 1), hop):
        frames.append(list(samples[start : start + size]))
    return frames or [list(samples)]


def _mel_points(low_hz: float = 80.0, high_hz: float = 3800.0, count: int = N_MELS) -> list[float]:
    def to_mel(hz: float) -> float:
        return 2595.0 * math.log10(1.0 + hz / 700.0)

    def to_hz(mel: float) -> float:
        return 700.0 * (10 ** (mel / 2595.0) - 1.0)

    low, high = to_mel(low_hz), to_mel(high_hz)
    return [to_hz(low + (high - low) * index / (count + 1)) for index in range(count + 2)]


def mfcc(samples: Sequence[float], rate: int = RATE, *, n_mfcc: int = N_MFCC) -> list[list[float]]:
    if not samples:
        raise SpeechError("no samples")
    if rate < 4000:
        raise SpeechError("the sample rate is too low for speech")
    points = _mel_points(high_hz=min(3800.0, rate / 2 - 100))
    coefficients: list[list[float]] = []
    for frame in _frames(samples, rate):
        emphasised = [frame[index] - 0.97 * frame[index - 1] for index in range(1, len(frame))]
        windowed = [
            value * (0.54 - 0.46 * math.cos(2 * math.pi * index / max(1, len(emphasised) - 1)))
            for index, value in enumerate(emphasised)
        ]
        transformed = spectrum(windowed)
        bins = len(transformed) // 2
        power = [abs(transformed[index]) ** 2 / max(1, bins) for index in range(bins)]
        hz_per_bin = rate / 2 / max(1, bins)
        energies = []
        for band in range(len(points) - 2):
            low, centre, high = points[band], points[band + 1], points[band + 2]
            total = 0.0
            weight_sum = 0.0
            for index in range(bins):
                hz = index * hz_per_bin
                if low <= hz <= high:
                    weight = (hz - low) / max(1e-9, centre - low) if hz <= centre else (high - hz) / max(1e-9, high - centre)
                    total += power[index] * weight
                    weight_sum += weight
            energies.append(math.log(max(1e-12, total / max(1e-9, weight_sum))))
        coefficients.append(
            [
                sum(
                    energies[band] * math.cos(math.pi * order * (band + 0.5) / len(energies))
                    for band in range(len(energies))
                )
                for order in range(n_mfcc)
            ]
        )
    return coefficients


def dtw_distance(left: Sequence[Sequence[float]], right: Sequence[Sequence[float]]) -> float:
    if not left or not right:
        raise SpeechError("both sequences need frames")
    rows, columns = len(left), len(right)
    previous = [float("inf")] * (columns + 1)
    previous[0] = 0.0
    for row in range(1, rows + 1):
        current = [float("inf")] * (columns + 1)
        for column in range(1, columns + 1):
            cost = math.sqrt(sum((a - b) ** 2 for a, b in zip(left[row - 1], right[column - 1], strict=True)))
            current[column] = cost + min(previous[column], current[column - 1], previous[column - 1])
        previous = current
    return round(previous[columns] / max(rows, columns), 4)


class KeywordSpotter:
    """Template matching over MFCCs; it knows only the words it was trained on."""

    def __init__(self, *, threshold: float = 40.0) -> None:
        if threshold <= 0:
            raise SpeechError("the threshold must be positive")
        self.threshold = threshold
        self.templates: dict[str, list[list[list[float]]]] = {}

    def train(self, word: str, samples: Sequence[float], rate: int = RATE) -> dict[str, Any]:
        if not word.strip():
            raise SpeechError("a word needs a name")
        name = word.strip().lower()
        frames = mfcc(samples, rate)
        self.templates.setdefault(name, []).append(frames)
        return {"word": name, "frames": len(frames), "templates": len(self.templates[name])}

    def recognise(self, samples: Sequence[float], rate: int = RATE) -> dict[str, Any]:
        if not self.templates:
            raise SpeechError("train at least one word first")
        frames = mfcc(samples, rate)
        scores = []
        for word, stored in self.templates.items():
            best = min(dtw_distance(frames, template) for template in stored)
            scores.append({"word": word, "distance": best})
        scores.sort(key=lambda row: row["distance"])
        best = scores[0]
        runner_up = scores[1]["distance"] if len(scores) > 1 else best["distance"] + self.threshold
        return {
            "word": best["word"] if best["distance"] <= self.threshold else None,
            "distance": best["distance"],
            "threshold": self.threshold,
            "margin": round(runner_up - best["distance"], 4),
            "scores": scores,
            "accepted": best["distance"] <= self.threshold,
        }


def _vowel(formants: Sequence[float], seconds: float, rate: int) -> list[float]:
    count = max(1, int(seconds * rate))
    samples = []
    for index in range(count):
        moment = index / rate
        envelope = math.sin(math.pi * index / count) ** 0.6
        value = 0.0
        for order, formant in enumerate(formants):
            value += math.sin(2 * math.pi * formant * moment) / (order + 1.4)
        value += 0.25 * math.sin(2 * math.pi * 120 * moment)
        samples.append(0.35 * envelope * value)
    return samples


def _consonant(kind: str, seconds: float, rate: int, seed: int) -> list[float]:
    count = max(1, int(seconds * rate))
    state = seed
    samples = []
    for index in range(count):
        state = (state * 6364136223846793005 + 1442695040888963407) % (2**64)
        noise = (state >> 33) / (2**31) - 1.0
        envelope = math.sin(math.pi * index / count)
        if kind in {"s", "f"}:
            samples.append(0.16 * envelope * noise)
        elif kind in {"p", "t", "k"}:
            samples.append(0.22 * envelope * noise * (1 - index / count))
        else:
            samples.append(0.12 * envelope * noise)
    return samples


def formant_speak(text: str, *, rate: int = RATE, speed: float = 1.0) -> list[float]:
    if not text.strip():
        raise SpeechError("there is nothing to say")
    if speed <= 0:
        raise SpeechError("speed must be positive")
    samples: list[float] = []
    for index, character in enumerate(text.lower()):
        if character in VOWELS:
            samples.extend(_vowel(VOWELS[character], 0.11 / speed, rate))
        elif character in NOISE:
            samples.extend(_consonant(character, 0.05 / speed, rate, index + 1))
        elif character == " ":
            samples.extend([0.0] * int(0.05 * rate))
        elif character.isdigit():
            samples.extend(_vowel(VOWELS["i"], 0.09 / speed, rate))
        else:
            samples.extend(_vowel(VOWELS["e"], 0.07 / speed, rate))
    if not samples:
        raise SpeechError("the text produced no sound")
    return normalise(samples, peak=0.8)


def speak(text: str, path: str | os.PathLike[str], *, rate: int = RATE, speed: float = 1.0) -> dict[str, Any]:
    started = time.perf_counter()
    samples = formant_speak(text, rate=rate, speed=speed)
    target = write_wav(path, samples, rate=rate)
    return {
        "path": str(target),
        "text": text,
        "seconds": round(len(samples) / rate, 3),
        "rate": rate,
        "synthesised_ms": round((time.perf_counter() - started) * 1000, 2),
        "method": "formant synthesis",
    }


def listen(path: str | os.PathLike[str], spotter: KeywordSpotter) -> dict[str, Any]:
    wav = read_wav(str(path))
    samples = wav["samples"]
    if max((abs(value) for value in samples), default=0) > 1.5:
        samples = [value / 32768.0 for value in samples]
    result = spotter.recognise(samples, wav["rate"])
    return {"path": str(path), "rate": wav["rate"], **result}
