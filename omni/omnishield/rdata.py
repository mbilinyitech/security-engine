"""Export conversation and answer data as CSV, then let R analyse it.

Python writes two tidy tables: one row per conversation line, one row per
question answered. R reads them and reports language mix, confidence, drift and
latency quantiles. Nothing here is estimated: every number comes from the rows.
"""

from __future__ import annotations

import csv
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .answer import answer
from .language import ConversationTracker


class RDataError(Exception):
    pass


def _drift_by_line(tracker: ConversationTracker) -> dict[int, float]:
    return {row["line"]: row["drift"] for row in tracker.drift()}


def export_conversation(path: str | Path, tracker: ConversationTracker) -> dict[str, Any]:
    if not tracker.lines:
        raise RDataError("the tracker has no lines")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    drift = _drift_by_line(tracker)
    with open(target, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["line", "at", "speaker", "language", "confidence", "terms", "drift"])
        for index, line in enumerate(tracker.lines):
            writer.writerow(
                [
                    index,
                    line["at"],
                    line["speaker"],
                    line["language"],
                    line["confidence"],
                    "|".join(line["terms"]),
                    round(drift.get(index, 0.0), 4),
                ]
            )
    return {"path": str(target), "rows": len(tracker.lines), "bytes": target.stat().st_size}


def export_answers(
    path: str | Path,
    questions: Sequence[str],
    passages: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    if not questions:
        raise RDataError("there are no questions")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["question", "confidence", "top_score", "latency_ms", "citations", "sources", "method"])
        rows = 0
        for question in questions:
            result = answer(question, passages)
            writer.writerow(
                [
                    question,
                    result["confidence"],
                    result.get("top_score", 0.0),
                    result["latency_ms"],
                    len(result["citations"]),
                    "|".join(sorted({row["source"] for row in result["citations"]})),
                    result["method"],
                ]
            )
            rows += 1
    return {"path": str(target), "rows": rows, "bytes": target.stat().st_size}


def export_all_csv(
    directory: str | Path,
    *,
    tracker: ConversationTracker | None = None,
    questions: Sequence[str] | None = None,
    passages: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"directory": str(root), "files": []}
    if tracker is not None:
        manifest["files"].append(export_conversation(root / "conversation.csv", tracker))
    if questions and passages:
        manifest["files"].append(export_answers(root / "answers.csv", questions, passages))
    if not manifest["files"]:
        raise RDataError("nothing to export: give a tracker or questions and passages")
    return manifest


def analyse_with_r(directory: str | Path, *, script: str | Path | None = None) -> dict[str, Any]:
    import shutil
    import subprocess

    executable = shutil.which("Rscript")
    if not executable:
        raise RDataError("Rscript is not installed")
    target = Path(script) if script else Path(__file__).resolve().parent.parent / "analysis" / "conversation.R"
    if not target.is_file():
        raise RDataError(f"no R script at {target}")
    started = time.perf_counter()
    completed = subprocess.run(
        [executable, str(target), str(directory)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise RDataError(f"R failed: {completed.stderr.strip()}")
    return {
        "script": str(target),
        "stdout": completed.stdout.strip(),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }
