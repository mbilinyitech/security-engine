"""Identify languages and follow a conversation as it moves.

Language identification uses two signals: the script (CJK, Arabic, Cyrillic,
Devanagari are unambiguous) and character trigrams compared with stopword
profiles by cosine. It reports a confidence and the runner-up, because a short
line is genuinely ambiguous.

The tracker records each line with its speaker, language and top terms, then
measures topic drift as 1 - cosine between consecutive term vectors. It learns
by writing those summaries to the knowledge store; it does not claim to
understand what people mean.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from collections.abc import Sequence
from typing import Any

WORD = re.compile(r"[^\W\d_]+", re.UNICODE)

STOPWORDS = {
    "sw": {"na", "ya", "kwa", "ni", "wa", "za", "la", "katika", "hii", "hilo", "kuwa", "sana", "lakini", "pia", "kama", "huyu", "watu", "mimi", "wewe", "yeye", "sisi", "nyinyi", "wao", "kila", "siku", "habari", "asante"},
    "en": {"the", "and", "of", "to", "in", "is", "are", "was", "for", "on", "with", "that", "this", "it", "as", "by", "be", "or", "from", "you", "we", "they", "have", "not"},
    "fr": {"le", "la", "les", "des", "et", "est", "une", "un", "du", "que", "qui", "dans", "pour", "pas", "sur", "avec", "ce", "il", "elle", "nous", "vous"},
    "es": {"el", "la", "los", "las", "de", "y", "es", "una", "un", "que", "en", "por", "para", "con", "no", "se", "su", "al", "como", "pero", "muy"},
    "pt": {"o", "a", "os", "as", "de", "e", "é", "um", "uma", "que", "em", "para", "com", "não", "se", "do", "da", "como", "mas", "muito"},
    "de": {"der", "die", "das", "und", "ist", "nicht", "ein", "eine", "mit", "für", "auf", "von", "zu", "den", "dem", "des", "sich", "auch", "wir", "sie"},
    "it": {"il", "lo", "la", "gli", "le", "di", "e", "è", "un", "una", "che", "in", "per", "con", "non", "si", "del", "della", "come", "ma", "molto"},
    "ru": {"и", "в", "не", "на", "что", "это", "как", "для", "с", "по", "из", "к", "но", "они", "мы", "вы", "он", "она", "быть", "очень"},
}
SEEDS = {
    "sw": "habari ya asubuhi na watu wa nyumbani",
    "en": "the quick brown fox jumps over the lazy dog",
    "fr": "le chat est dans la maison avec les enfants",
    "es": "el gato está en la casa con los niños",
    "pt": "o gato está na casa com as crianças",
    "de": "die katze ist im haus mit den kindern",
    "it": "il gatto è nella casa con i bambini",
    "ru": "кот в доме с детьми и очень рад",
}


class LanguageError(Exception):
    pass


def _trigrams(text: str) -> Counter[str]:
    cleaned = " ".join(WORD.findall(text.lower()))
    grams: Counter[str] = Counter()
    for index in range(len(cleaned) - 2):
        grams[cleaned[index : index + 3]] += 1
    return grams


def _cosine(left: Counter[str], right: Counter[str]) -> float:
    if not left or not right:
        return 0.0
    common = set(left) & set(right)
    numerator = sum(left[gram] * right[gram] for gram in common)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    return numerator / (left_norm * right_norm or 1.0)


def _script(text: str) -> str | None:
    for character in text:
        code = ord(character)
        if 0x4E00 <= code <= 0x9FFF:
            return "zh"
        if 0x0600 <= code <= 0x06FF:
            return "ar"
        if 0x0400 <= code <= 0x04FF:
            return "ru"
        if 0x0900 <= code <= 0x097F:
            return "hi"
    return None


_PROFILES = {
    language: _trigrams(seed + " " + " ".join(sorted(words)) + " " + " ".join(sorted(words)))
    for language, (seed, words) in {key: (SEEDS[key], STOPWORDS[key]) for key in SEEDS}.items()
}


def identify(text: str) -> dict[str, Any]:
    if not text.strip():
        raise LanguageError("there is no text to identify")
    script = _script(text)
    if script:
        return {"language": script, "confidence": 1.0, "method": "script", "scores": {script: 1.0}}
    grams = _trigrams(text)
    if not grams:
        raise LanguageError("there are no letters to identify")
    scores = {language: round(_cosine(grams, profile), 4) for language, profile in _PROFILES.items()}
    ordered = sorted(scores.items(), key=lambda pair: -pair[1])
    best, second = ordered[0], ordered[1]
    margin = max(0.0, best[1] - second[1])
    return {
        "language": best[0],
        "confidence": round(min(1.0, best[1] * 0.6 + margin * 2.0), 4),
        "runner_up": second[0],
        "margin": round(margin, 4),
        "method": "character trigrams",
        "scores": dict(ordered[:4]),
    }


class ConversationTracker:
    """Per-line language, terms and topic drift for a stream of messages."""

    def __init__(self, *, window: int = 5) -> None:
        if window < 2:
            raise LanguageError("the window needs at least two lines")
        self.window = window
        self.lines: list[dict[str, Any]] = []

    def observe(self, speaker: str, text: str, *, at: float | None = None) -> dict[str, Any]:
        if not speaker.strip():
            raise LanguageError("a line needs a speaker")
        detected = identify(text)
        terms = [word.lower() for word in WORD.findall(text) if len(word) > 2][:12]
        line = {
            "speaker": speaker.strip(),
            "text": text.strip(),
            "at": round(at if at is not None else time.time(), 3),
            "language": detected["language"],
            "confidence": detected["confidence"],
            "terms": terms,
        }
        self.lines.append(line)
        return line

    def _vector(self, lines: Sequence[dict[str, Any]]) -> Counter[str]:
        return Counter(term for line in lines for term in line["terms"])

    def drift(self) -> list[dict[str, Any]]:
        series = []
        for index in range(self.window, len(self.lines)):
            previous = self._vector(self.lines[index - self.window : index])
            current = self._vector(self.lines[index - self.window + 1 : index + 1])
            distance = 1.0 - _cosine(previous, current)
            series.append({"line": index, "drift": round(distance, 4), "speaker": self.lines[index]["speaker"]})
        return series

    def summary(self) -> dict[str, Any]:
        if not self.lines:
            return {"lines": 0, "languages": {}, "speakers": {}, "topics": [], "drift": []}
        languages = Counter(line["language"] for line in self.lines)
        speakers = Counter(line["speaker"] for line in self.lines)
        topics = self._vector(self.lines).most_common(8)
        return {
            "lines": len(self.lines),
            "languages": dict(languages.most_common()),
            "speakers": dict(speakers.most_common()),
            "topics": [{"term": term, "count": count} for term, count in topics],
            "mean_drift": round(sum(row["drift"] for row in self.drift()) / max(1, len(self.drift())), 4),
            "drift": self.drift()[-5:],
        }

    def learn(self, store: Any) -> dict[str, Any]:
        summary = self.summary()
        if not summary["lines"]:
            raise LanguageError("there is nothing to learn yet")
        text = (
            f"Conversation of {summary['lines']} lines between "
            f"{', '.join(summary['speakers'])} in languages "
            f"{', '.join(summary['languages'])}. Top terms: "
            f"{', '.join(item['term'] for item in summary['topics'])}. "
            f"Mean topic drift {summary['mean_drift']}."
        )
        store.add(text, source="conversation", title="conversation summary", tags=["language", "conversation"])
        return {"text": text, **summary}
