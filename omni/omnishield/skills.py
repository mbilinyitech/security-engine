"""Named skills with declared parameters, so anything the system can do is callable.

A skill is a name, a summary, the parameters it accepts and a function that
returns JSON-able data. The registry is introspectable: `skill list` shows what
exists, `skill run` validates the parameters before calling anything.

Skills wrap real modules; they add no capability that is not already tested
there. What they add is a stable, uniform surface.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class SkillError(Exception):
    pass


@dataclass(frozen=True)
class Skill:
    name: str
    summary: str
    parameters: dict[str, bool]
    run: Callable[[dict[str, Any]], dict[str, Any]]
    examples: list[str] = field(default_factory=list)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "parameters": self.parameters,
            "examples": self.examples,
        }


def _answer(params: dict[str, Any]) -> dict[str, Any]:
    from .answer import analyse
    from .knowledge import KnowledgeStore

    store = KnowledgeStore.open(params["store"])
    passages = [{"text": item.get("text", ""), "source": item.get("source", ""), "title": item.get("title", "")} for item in store.items]
    document = analyse(params["question"], passages)
    answer = document["answer"]
    return {
        "text": answer["answer"],
        "citations": answer["citations"],
        "confidence": answer["confidence"],
        "latency_ms": answer["latency_ms"],
        "matrix_shape": document["matrix_shape"],
        "equilibrium_top": document["equilibrium_top"],
        "logistic_bias": document["logistic"]["bias"],
    }


def _think(params: dict[str, Any]) -> dict[str, Any]:
    from .knowledge import KnowledgeStore
    from .think import think

    return think(params["question"], KnowledgeStore.open(params["store"]), depth=int(params.get("depth", 4)))


def _pathtrace(params: dict[str, Any]) -> dict[str, Any]:
    from .three_d import pathtrace

    return pathtrace(params["scene"], params["out"])


def _denoise(params: dict[str, Any]) -> dict[str, Any]:
    from .render import Canvas, denoise, noise_level, read_ppm

    with open(params["image"], "rb") as handle:
        width, height, rows = read_ppm(handle.read())
    canvas = Canvas(width, height)
    for y, row in enumerate(rows):
        for x, pixel in enumerate(row):
            canvas.set(x, y, pixel)
    cleaned = denoise(canvas, radius=int(params.get("radius", 2)))
    saved = cleaned.save_png(params["out"])
    return {
        "noise_before": noise_level(canvas),
        "noise_after": noise_level(cleaned),
        "png": str(saved),
        "png_bytes": saved.stat().st_size,
    }


def _omni_say(params: dict[str, Any]) -> dict[str, Any]:
    from .omnilang import Lexicon, speak

    lexicon = Lexicon(params["lexicon"])
    for concept in (params["subject"], params["verb"]) + ((params["object"],) if params.get("object") else ()):
        lexicon.learn(concept)
    lexicon.save()
    return {"omni": speak(lexicon, params["subject"], params["verb"], params.get("object"), tense=params.get("tense", "present"))}


def _omni_translate(params: dict[str, Any]) -> dict[str, Any]:
    from .omnilang import Lexicon, translate

    lexicon = Lexicon(params["lexicon"])
    result = translate(lexicon, params["text"])
    lexicon.save()
    return result


def _corpus(params: dict[str, Any]) -> dict[str, Any]:
    from .corpus import learn_book, learn_dictionary, learn_directory
    from .knowledge import KnowledgeStore
    from .omnilang import Lexicon

    store = KnowledgeStore.open(params["store"])
    lexicon = Lexicon(params["lexicon"])
    if params.get("directory"):
        return learn_directory(store, lexicon, params["directory"])
    if params.get("dictionary"):
        return learn_dictionary(store, lexicon, params["dictionary"])
    return learn_book(store, lexicon, params["book"])


def _study(params: dict[str, Any]) -> dict[str, Any]:
    import json
    from pathlib import Path

    from .knowledge import KnowledgeStore
    from .omnilang import Lexicon
    from .selfstudy import run

    passages = [json.loads(line) for line in Path(params["file"]).read_text(encoding="utf-8").splitlines() if line.strip()]
    return run(passages, KnowledgeStore.open(params["store"]), Lexicon(params["lexicon"]), rounds=int(params.get("rounds", 1)))


def _chat(params: dict[str, Any]) -> dict[str, Any]:
    from .knowledge import KnowledgeStore
    from .net import Node, envelope

    host, _, port = params["peer"].partition(":")
    node = Node(params.get("id", "client"), store=KnowledgeStore.open(params["store"]))
    return node.send(host or "127.0.0.1", int(port), envelope("chat", node.id, {"text": params["text"]})) or {}


def _speak(params: dict[str, Any]) -> dict[str, Any]:
    from .speech import speak

    return speak(params["text"], params["out"], speed=float(params.get("speed", 1.0)))


def _telemetry(params: dict[str, Any]) -> dict[str, Any]:
    from .stream import Telemetry, simulate_air

    telemetry = Telemetry(params["path"], window=int(params.get("window", 60)))
    if params.get("simulate", True):
        for sample in simulate_air(int(params.get("minutes", 60))):
            telemetry.ingest(sample)
    return {"stats": telemetry.stats(), "alerts": telemetry.alerts()}


def _language(params: dict[str, Any]) -> dict[str, Any]:
    from .language import identify

    return identify(params["text"])


SKILLS: dict[str, Skill] = {
    skill.name: skill
    for skill in (
        Skill("answer", "Retrieve passages and answer with BM25, a TF-IDF matrix, power iteration and softmax.", {"question": True, "store": False}, _answer, ['{"question": "what is bm25"}']),
        Skill("think", "Deliberate in steps: sub-questions, evidence, disagreement check, coverage.", {"question": True, "store": False, "depth": False}, _think, ['{"question": "how does it render", "depth": 3}']),
        Skill("pathtrace", "Render a JSON scene with global illumination and save a PNG.", {"scene": True, "out": True}, _pathtrace, ['{"scene": "scenes/studio.json", "out": "/tmp/studio.png"}']),
        Skill("denoise", "Edge-preserving bilateral filter over a PPM, measured before and after.", {"image": True, "out": True, "radius": False}, _denoise, ['{"image": "/tmp/raw.ppm", "out": "/tmp/clean.png"}']),
        Skill("omni_say", "Render one sentence in the Omni constructed language.", {"subject": True, "verb": True, "object": False, "tense": False, "lexicon": False}, _omni_say, ['{"subject": "person", "verb": "see", "object": "sun", "tense": "past"}']),
        Skill("omni_translate", "Turn words into Omni roots, learning anything new.", {"text": True, "lexicon": False}, _omni_translate, ['{"text": "person speaks water"}']),
        Skill("corpus", "Learn a book, a dictionary or a directory of both.", {"store": False, "lexicon": False, "book": False, "dictionary": False, "directory": False}, _corpus, ['{"dictionary": "swahili.dict"}']),
        Skill("study", "Run a self-study curriculum over a JSONL file of passages.", {"file": True, "store": False, "lexicon": False, "rounds": False}, _study, ['{"file": "passages.jsonl", "rounds": 3}']),
        Skill("chat", "Ask a peer a question over OmniNet.", {"peer": True, "text": True, "id": False, "store": False}, _chat, ['{"peer": "127.0.0.1:7701", "text": "what are frames"}']),
        Skill("speak", "Speak text as a WAV with formant synthesis.", {"text": True, "out": True, "speed": False}, _speak, ['{"text": "habari", "out": "/tmp/h.wav"}']),
        Skill("telemetry", "Ingest air readings, keep a window and report alerts.", {"path": True, "window": False, "minutes": False, "simulate": False}, _telemetry, ['{"path": "/tmp/air.jsonl", "minutes": 30}']),
        Skill("language", "Identify the language of a line.", {"text": True}, _language, ['{"text": "habari ya asubuhi"}']),
    )
}


def registry() -> list[dict[str, Any]]:
    return [SKILLS[name].describe() for name in sorted(SKILLS)]


def run(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    if name not in SKILLS:
        raise SkillError(f"unknown skill {name}")
    skill = SKILLS[name]
    supplied = dict(params or {})
    unknown = sorted(set(supplied) - set(skill.parameters))
    if unknown:
        raise SkillError(f"{name} does not take {', '.join(unknown)}")
    missing = sorted(key for key, required in skill.parameters.items() if required and not supplied.get(key))
    if missing:
        raise SkillError(f"{name} needs {', '.join(missing)}")
    started = time.perf_counter()
    result = skill.run(supplied)
    if not isinstance(result, dict):
        raise SkillError(f"{name} did not return an object")
    signature = inspect.signature(skill.run)
    if len(signature.parameters) != 1:
        raise SkillError(f"{name} has a bad signature")
    return {"skill": name, "ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "result": result}
