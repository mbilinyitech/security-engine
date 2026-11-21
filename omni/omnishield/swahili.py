"""Small, honest reasoning over Swahili sentences.

A fixed set of Swahili patterns is parsed into facts and rules, then forward
chaining answers a question with a proof. Anything outside the patterns is
reported as unparsed instead of guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any


class SwahiliError(Exception):
    pass


ALL = re.compile(r"^(?:kila|wote)\s+(\w+)\s+ni\s+(\w+)$")
NONE = re.compile(r"^hakuna\s+(\w+)\s+ni\s+(\w+)$")
SOME = re.compile(r"^baadhi(?:\s+ya)?\s+(\w+)\s+ni\s+(\w+)$")
IS = re.compile(r"^(\w+)\s+ni\s+(\w+)$")
NOT = re.compile(r"^(\w+)\s+si\s+(\w+)$")


def _normalise(text: str) -> str:
    cleaned = re.sub(r"[.,!?;:\"']", "", text.strip().lower())
    return re.sub(r"\s+", " ", cleaned)


def parse(sentence: str) -> dict[str, Any]:
    text = _normalise(sentence)
    if not text:
        raise SwahiliError("an empty sentence cannot be parsed")
    for pattern, kind in ((ALL, "all"), (NONE, "none"), (SOME, "some")):
        match = pattern.match(text)
        if match:
            return {"kind": kind, "subject": match.group(1), "object": match.group(2), "text": text}
    match = NOT.match(text)
    if match:
        return {"kind": "not", "entity": match.group(1), "class": match.group(2), "text": text}
    match = IS.match(text)
    if match:
        return {"kind": "is", "entity": match.group(1), "class": match.group(2), "text": text}
    return {"kind": "unparsed", "text": text}


def _answer(
    question: dict[str, Any],
    facts: set[tuple[str, str]],
    denials: set[tuple[str, str]],
    rules: Sequence[dict[str, Any]],
) -> tuple[str, list[str]]:
    if question["kind"] == "is":
        key = (question["entity"], question["class"])
        if key in facts:
            return "ndiyo", []
        if key in denials:
            return "hapana", []
        if any(
            rule["subject"] == question["entity"] and rule["object"] == question["class"]
            for rule in rules
        ):
            return "ndiyo", [f"'{question['entity']}' falls under '{question['class']}' by a rule"]
        return "sijui", []
    if question["kind"] == "not":
        key = (question["entity"], question["class"])
        if key in denials:
            return "ndiyo", []
        if key in facts:
            return "hapana", []
        return "sijui", []
    raise SwahiliError("the question must be of the form 'X ni Y' or 'X si Y'")


def swahili_reasoning(statements: Sequence[str], question: str) -> dict[str, Any]:
    if not statements:
        raise SwahiliError("no statements were given")
    parsed = [parse(item) for item in statements]
    rules = [item for item in parsed if item["kind"] == "all"]
    denials_rules = [item for item in parsed if item["kind"] == "none"]
    facts = {
        (item["entity"], item["class"]) for item in parsed if item["kind"] == "is"
    }
    denials = {
        (item["entity"], item["class"]) for item in parsed if item["kind"] == "not"
    }
    proof: list[str] = []
    changed = True
    while changed:
        changed = False
        for rule in rules:
            for entity, klass in list(facts):
                if klass != rule["subject"]:
                    continue
                derived = (entity, rule["object"])
                if derived not in facts:
                    facts.add(derived)
                    proof.append(
                        f"'{rule['text']}' + '{entity} ni {klass}' -> '{entity} ni {rule['object']}'"
                    )
                    changed = True
            for other in rules:
                if rule["object"] != other["subject"]:
                    continue
                derived_rule = {
                    "kind": "all",
                    "subject": rule["subject"],
                    "object": other["object"],
                    "text": f"{rule['subject']} -> {other['object']}",
                }
                if derived_rule not in rules:
                    rules.append(derived_rule)
                    proof.append(
                        f"'{rule['text']}' + '{other['text']}' -> 'kila {rule['subject']} ni {other['object']}'"
                    )
                    changed = True
        for rule in denials_rules:
            for entity, klass in list(facts):
                if klass != rule["subject"]:
                    continue
                derived = (entity, rule["object"])
                if derived not in denials:
                    denials.add(derived)
                    proof.append(
                        f"'{rule['text']}' + '{entity} ni {klass}' -> '{entity} si {rule['object']}'"
                    )
                    changed = True
    parsed_question = parse(question)
    answer, extra = _answer(parsed_question, facts, denials, rules)
    return {
        "answer": answer,
        "entailed": answer == "ndiyo",
        "contradicted": answer == "hapana",
        "proof": proof + extra,
        "parsed": [item for item in parsed if item["kind"] != "unparsed"],
        "unparsed": [item["text"] for item in parsed if item["kind"] == "unparsed"],
        "question": parsed_question,
    }


def translate_connectives(text: str) -> str:
    """Map the common logical connectives, leaving the rest untouched."""
    mapping = [
        (r"\bkama\b", "if"),
        (r"\bbasi\b", "then"),
        (r"\bna\b", "and"),
        (r"\bau\b", "or"),
        (r"\bsi\b", "not"),
        (r"\bkwa hiyo\b", "therefore"),
        (r"\bkwa sababu\b", "because"),
        (r"\bkila\b", "every"),
        (r"\bhakuna\b", "no"),
        (r"\bbaadhi\b", "some"),
    ]
    output = _normalise(text)
    for pattern, word in mapping:
        output = re.sub(pattern, word, output)
    return output
