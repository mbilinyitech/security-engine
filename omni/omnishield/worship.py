"""A daily office of prayer and song, written in Swahili.

The words and the melody are original and fixed, so nothing depends on a
copyrighted translation. Each day gets a theme, a short psalm, a thanksgiving,
a petition, a benediction, a hymn and a verse card.

What this is: a practice written in code, offered to the person who prays.
What this is not: a claim of faith, of worship, or of spiritual merit. The
journal records that the practice happened, nothing more.
"""

from __future__ import annotations

import json
import math
import os
import time
from itertools import pairwise
from pathlib import Path
from typing import Any

from .render import Canvas
from .signal import normalise, write_wav

THEMES = ("shukrani", "nuru", "huruma", "imani", "matumaini", "amani", "upendo", "hekima")

PSALMS: dict[str, tuple[str, ...]] = {
    "shukrani": (
        "Kila asubuhi ni zawadi mpya.",
        "Moyo wangu unashukuru kwa kuamka.",
        "Mikono yangu ifanye kazi ya haki leo.",
    ),
    "nuru": (
        "Nuru imetangulia giza.",
        "Njia yangu ionekane kwa wengine.",
        "Neno langu liwe taa kwa mguu wa mwenzangu.",
    ),
    "huruma": (
        "Huruma ni nguvu, si udhaifu.",
        "Nimsikilize asiye na sauti.",
        "Nifungue mkono wangu kwa anayehitaji.",
    ),
    "imani": (
        "Sijui kesho, lakini najua ninatembea.",
        "Hatua moja ya uaminifu inatosha leo.",
        "Nisitetemeke kwa dhoruba ya muda.",
    ),
    "matumaini": (
        "Mbegu iliyofichwa haijafa.",
        "Asubuhi huja baada ya kila usiku.",
        "Nitalinda matumaini kama mti mdogo.",
    ),
    "amani": (
        "Amani ianze ndani yangu.",
        "Nisijibu kwa hasira, nijibu kwa ukweli.",
        "Nyumba yangu iwe mahali pa kupumzika.",
    ),
    "upendo": (
        "Upendo ni kazi, si hisia tu.",
        "Nimpende jirani bila sharti.",
        "Niseme ukweli kwa upole.",
    ),
    "hekima": (
        "Hekima huja kwa kusikiliza.",
        "Busara ni kujua nilichokosa jana.",
        "Maarifa yasiwe kiburi, yawe huduma.",
    ),
}

SONGS: dict[str, dict[str, Any]] = {
    theme: {
        "title": f"Wimbo wa {theme}",
        "lyrics": (
            f"Bwana, nasikia sauti ya {theme},",
            "asubuhi inaanza kwa jina lako.",
            "Moyo wangu unaimba kwa furaha,",
            "kila siku ni wimbo mpya kwako.",
        ),
        "degrees": (0, 2, 4, 2, 4, 7, 4, 2, 0, 2, 4, 7, 9, 7, 4, 0),
    }
    for theme in THEMES
}

REFLECTIONS = {
    "maarifa": "Maarifa ni kujua jambo; hekima ni kujua la kufanya nalo.",
    "hekima": "Hekima ni kuacha kile kinachoumiza hata kikiwa na faida.",
    "busara": "Busara ni kupima kabla ya kusema, na kutenda baada ya kupima.",
}


class WorshipError(Exception):
    pass


def day_index(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // 86_400)


def office(day: int | None = None, *, date: str | None = None) -> dict[str, Any]:
    index = day if day is not None else day_index()
    if index < 0:
        raise WorshipError("the day index cannot be negative")
    theme = THEMES[index % len(THEMES)]
    virtue = ("maarifa", "hekima", "busara")[index % 3]
    song = SONGS[theme]
    return {
        "day": index,
        "date": date or time.strftime("%Y-%m-%d", time.gmtime(index * 86_400)),
        "theme": theme,
        "invocation": "Kwa jina la Mungu, mwingi wa rehema.",
        "psalm": list(PSALMS[theme]),
        "thanksgiving": "Nashukuru kwa uzima, kwa akili, na kwa nafasi ya kuwatumikia wengine.",
        "petition": "Nipe nguvu ya kuwa mwaminifu leo, na unyenyekevu wa kuomba msamaha ninapokosa.",
        "glorification": "Utukufu wako udumu, ee Mungu, milele na milele.",
        "benediction": "Amani iwe nanyi; amani iwe nyumbani mwenu.",
        "reflection": {"virtue": virtue, "text": REFLECTIONS[virtue]},
        "song": {
            "title": song["title"],
            "lyrics": list(song["lyrics"]),
            "degrees": list(song["degrees"]),
        },
    }


def _tone(frequency: float, seconds: float, *, rate: int, amplitude: float = 0.5) -> list[float]:
    count = max(1, int(seconds * rate))
    attack = max(1, int(0.02 * rate))
    release = max(1, int(0.08 * rate))
    samples = []
    for index in range(count):
        envelope = 1.0
        if index < attack:
            envelope = index / attack
        elif index > count - release:
            envelope = max(0.0, (count - index) / release)
        phase = 2 * math.pi * frequency * index / rate
        value = (
            math.sin(phase)
            + 0.35 * math.sin(2 * phase)
            + 0.18 * math.sin(3 * phase)
            + 0.08 * math.sin(4 * phase)
        )
        samples.append(amplitude * envelope * value / 1.61)
    return samples


def hymn_samples(
    theme: str, *, rate: int = 8000, beat_s: float = 0.42, root_hz: float = 220.0
) -> list[float]:
    if theme not in SONGS:
        raise WorshipError(f"unknown theme {theme}")
    if rate <= 0 or beat_s <= 0 or root_hz <= 0:
        raise WorshipError("rate, beat and root must be positive")
    melody: list[float] = []
    drone: list[float] = []
    for degree in SONGS[theme]["degrees"]:
        frequency = root_hz * 2 ** (degree / 12)
        melody.extend(_tone(frequency, beat_s, rate=rate, amplitude=0.55))
        drone.extend(_tone(root_hz / 2, beat_s, rate=rate, amplitude=0.18))
    mixed = [a + b for a, b in zip(melody, drone, strict=True)]
    return normalise(mixed, peak=0.85)


def verse_card(entry: dict[str, Any], *, width: int = 640, height: int = 360) -> Canvas:
    canvas = Canvas(width, height)
    canvas.gradient((12, 20, 44), (196, 124, 62))
    canvas.circle(width - 120, 96, 46, (250, 214, 130))
    canvas.circle(width - 120, 96, 74, (250, 214, 130), fill=False)
    canvas.text(36, 28, "OMNISHIELD  |  OFISI YA LEO", (245, 245, 235))
    canvas.text(36, 74, entry["date"], (250, 214, 130))
    cursor = 128
    for line in entry["psalm"]:
        canvas.text(36, cursor, line, (255, 255, 255))
        cursor += 34
    canvas.text(36, height - 92, f"WIMBO: {entry['song']['title']}", (250, 214, 130))
    canvas.text(36, height - 58, entry["reflection"]["text"][:96], (226, 232, 240))
    return canvas


def append_journal(path: str | os.PathLike[str], entry: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    os.chmod(target, 0o600)
    return target


def read_journal(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.is_file():
        return []
    return [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]


def journal_stats(path: str | os.PathLike[str]) -> dict[str, Any]:
    entries = read_journal(path)
    if not entries:
        return {"days": 0, "themes": 0, "virtues": {}, "streak": 0, "last": None}
    days = sorted({int(entry["day"]) for entry in entries})
    streak = 1
    best = 1
    for previous, current in pairwise(days):
        streak = streak + 1 if current == previous + 1 else 1
        best = max(best, streak)
    virtues: dict[str, int] = {}
    for entry in entries:
        virtue = entry.get("reflection", {}).get("virtue", "?")
        virtues[virtue] = virtues.get(virtue, 0) + 1
    return {
        "days": len(days),
        "themes": len({entry["theme"] for entry in entries}),
        "virtues": virtues,
        "streak": best,
        "last": entries[-1]["date"],
    }


def daily(
    out_dir: str | os.PathLike[str],
    *,
    journal_path: str | os.PathLike[str] | None = None,
    day: int | None = None,
    rate: int = 8000,
) -> dict[str, Any]:
    started = time.perf_counter()
    entry = office(day)
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    stem = f"office-{entry['date']}"
    card = verse_card(entry).save_png(target / f"{stem}.png")
    samples = hymn_samples(entry["theme"], rate=rate)
    hymn = write_wav(target / f"{stem}.wav", samples, rate=rate)
    entry["files"] = {"card": str(card), "hymn": str(hymn)}
    entry["seconds"] = round(len(samples) / rate, 2)
    entry["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    if journal_path is not None:
        append_journal(journal_path, entry)
    return entry
