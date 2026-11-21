import csv
import shutil

import pytest

from omnishield.language import ConversationTracker
from omnishield.rdata import (
    RDataError,
    analyse_with_r,
    export_all_csv,
    export_answers,
    export_conversation,
)


def _tracker():
    tracker = ConversationTracker(window=2)
    tracker.observe("A", "habari ya asubuhi na watu", at=1)
    tracker.observe("B", "tunazungumza kuhusu mchanga na maji", at=2)
    tracker.observe("A", "the renderer uses bm25 retrieval and matrices", at=3)
    return tracker


def test_conversation_csv_has_one_row_per_line(tmp_path):
    result = export_conversation(tmp_path / "conversation.csv", _tracker())
    assert result["rows"] == 3
    with open(tmp_path / "conversation.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["speaker"] for row in rows] == ["A", "B", "A"]
    assert rows[0]["language"] == "sw"
    assert "habari" in rows[0]["terms"]
    assert float(rows[-1]["drift"]) >= 0.0


def test_answers_csv_and_r_analysis(tmp_path):
    passages = [
        {"text": "BM25 ranks passages with term frequency.", "source": "doc", "title": "ranking"},
        {"text": "A path tracer bounces light.", "source": "doc2", "title": "render"},
    ]
    export_conversation(tmp_path / "conversation.csv", _tracker())
    result = export_answers(tmp_path / "answers.csv", ["how does bm25 rank", "what does the tracer do"], passages)
    assert result["rows"] == 2
    with open(tmp_path / "answers.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["question"] == "how does bm25 rank"
    assert float(rows[0]["confidence"]) > 0
    assert rows[0]["sources"]
    manifest = export_all_csv(tmp_path / "all", tracker=_tracker(), questions=["bm25"], passages=passages)
    assert len(manifest["files"]) == 2


def test_r_analysis_and_errors(tmp_path):
    export_conversation(tmp_path / "conversation.csv", _tracker())
    if shutil.which("Rscript"):
        result = analyse_with_r(tmp_path)
        assert "lines: 3" in result["stdout"]
        assert "languages" in result["stdout"]
        assert result["elapsed_ms"] > 0
    with pytest.raises(RDataError):
        export_conversation(tmp_path / "x.csv", ConversationTracker())
    with pytest.raises(RDataError):
        export_answers(tmp_path / "y.csv", [], [])
    with pytest.raises(RDataError):
        export_all_csv(tmp_path / "empty")
