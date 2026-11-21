import pytest

from omnishield.answer import AnswerError, Evidence, analyse, answer

PASSAGES = [
    {"text": "BM25 ranks passages with term frequency and document frequency.", "source": "a"},
    {"text": "Power iteration finds the stationary distribution of a graph.", "source": "b"},
    {"text": "Swahili worship writes a psalm and a hymn each day.", "source": "c"},
]


def test_bm25_ranks_and_softmax_sums_to_one():
    evidence = Evidence(PASSAGES)
    ranked = evidence.bm25("stationary distribution graph")
    assert ranked[0]["passage"]["source"] == "b"
    weights = evidence.softmax([row["score"] for row in ranked])
    assert sum(weights) == pytest.approx(1.0)
    assert weights[0] == max(weights)
    mixed = evidence.softmax([3.0, 1.0, 0.5])
    assert mixed[0] > mixed[1] > mixed[2]
    with pytest.raises(AnswerError):
        evidence.bm25("the and of")


def test_answer_cites_and_refuses_unknown():
    result = answer("how does bm25 rank", PASSAGES)
    assert result["citations"][0]["source"] == "a"
    assert result["answer"].startswith("BM25 ranks")
    assert result["confidence"] == pytest.approx(1.0)
    assert result["latency_ms"] >= 0
    empty = answer("quantum chromodynamics lattice", PASSAGES)
    assert empty["citations"] == []
    assert "No passage" in empty["answer"]


def test_matrix_equilibrium_and_logistic():
    evidence = Evidence(PASSAGES)
    matrix = evidence.tfidf_matrix()
    assert len(matrix) == 3 and len(matrix[0]) == len(evidence.vocabulary)
    distribution = evidence.stationary(matrix)
    assert sum(distribution) == pytest.approx(1.0, abs=1e-9)
    assert all(value > 0 for value in distribution)
    model = evidence.logistic(matrix, [1, 0, 0], epochs=40)
    assert len(model["weights"]) == len(evidence.vocabulary)
    full = analyse("stationary distribution", PASSAGES)
    assert full["matrix_shape"] == [3, len(evidence.vocabulary)]
    assert full["equilibrium_top"]
    with pytest.raises(AnswerError):
        Evidence([])
