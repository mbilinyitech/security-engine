"""Answer questions by retrieving and weighing evidence, with the maths shown.

This is an extractive answer engine, not a language model. It does five real
things: BM25 retrieval, a TF-IDF matrix, power iteration for a stationary
distribution, gradient descent for a logistic scorer, and a softmax to combine
scores. It writes an answer from the passages it found and cites them. It never
invents text that is not in the store.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from collections.abc import Sequence
from typing import Any

WORD = re.compile(r"[a-z0-9']+")

STOPWORDS = {
    "the", "a", "an", "of", "to", "and", "in", "is", "are", "was", "were", "for",
    "on", "with", "as", "at", "by", "it", "this", "that", "be", "or", "from",
    "na", "ya", "kwa", "ni", "wa", "za", "la", "katika", "hii", "hilo", "kuwa",
}


class AnswerError(Exception):
    pass


def tokenise(text: str) -> list[str]:
    return [word for word in WORD.findall(text.lower()) if word not in STOPWORDS and len(word) > 1]


class Evidence:
    """BM25 over passages plus the matrices the answer path needs."""

    def __init__(self, passages: Sequence[dict[str, Any]]) -> None:
        if not passages:
            raise AnswerError("the store is empty")
        self.passages = []
        for index, item in enumerate(passages):
            text = str(item.get("text", "")).strip()
            if not text:
                continue
            self.passages.append(
                {
                    "id": index,
                    "text": text,
                    "title": item.get("title") or text[:48],
                    "source": item.get("source", "store"),
                    "tokens": tokenise(text),
                }
            )
        if not self.passages:
            raise AnswerError("no passage has text")
        self.frequencies = [Counter(passage["tokens"]) for passage in self.passages]
        self.lengths = [len(passage["tokens"]) for passage in self.passages]
        self.average_length = sum(self.lengths) / len(self.lengths) or 1.0
        self.document_frequency: Counter[str] = Counter()
        for frequency in self.frequencies:
            self.document_frequency.update(frequency.keys())
        self.vocabulary = sorted(self.document_frequency)
        self.position = {word: index for index, word in enumerate(self.vocabulary)}

    def bm25(self, query: str, *, k1: float = 1.5, b: float = 0.75) -> list[dict[str, Any]]:
        terms = tokenise(query)
        if not terms:
            raise AnswerError("the question has no usable terms")
        total = len(self.passages)
        scores = []
        for index, frequency in enumerate(self.frequencies):
            score = 0.0
            for term in terms:
                if term not in frequency:
                    continue
                idf = math.log(1 + (total - self.document_frequency[term] + 0.5) / (self.document_frequency[term] + 0.5))
                tf = frequency[term]
                norm = k1 * (1 - b + b * self.lengths[index] / self.average_length)
                score += idf * (tf * (k1 + 1)) / (tf + norm)
            if score > 0:
                scores.append({"passage": self.passages[index], "score": round(score, 4)})
        scores.sort(key=lambda row: -row["score"])
        return scores

    def tfidf_matrix(self) -> list[list[float]]:
        total = len(self.passages)
        matrix = []
        for frequency, length in zip(self.frequencies, self.lengths, strict=True):
            row = [0.0] * len(self.vocabulary)
            for term, count in frequency.items():
                idf = math.log((1 + total) / (1 + self.document_frequency[term])) + 1.0
                row[self.position[term]] = (count / max(1, length)) * idf
            norm = math.sqrt(sum(value * value for value in row)) or 1.0
            matrix.append([value / norm for value in row])
        return matrix

    def stationary(self, matrix: Sequence[Sequence[float]], *, iterations: int = 60, damping: float = 0.85) -> list[float]:
        """Power iteration on the column-normalised similarity graph."""
        size = len(matrix)
        if size == 0:
            raise AnswerError("the matrix is empty")
        transition = [[0.0] * size for _ in range(size)]
        for column in range(size):
            weight = sum(matrix[column][row] for row in range(size)) or 1.0
            for row in range(size):
                transition[row][column] = matrix[column][row] / weight
        vector = [1.0 / size] * size
        for _ in range(iterations):
            updated = [0.0] * size
            for row in range(size):
                total = sum(transition[row][column] * vector[column] for column in range(size))
                updated[row] = damping * total + (1 - damping) / size
            norm = sum(updated) or 1.0
            vector = [value / norm for value in updated]
        return vector

    def logistic(self, features: Sequence[Sequence[float]], labels: Sequence[int], *, rate: float = 0.5, epochs: int = 150) -> dict[str, Any]:
        if len(features) != len(labels):
            raise AnswerError("features and labels must line up")
        width = len(features[0])
        weights = [0.0] * width
        bias = 0.0
        for _ in range(epochs):
            gradient = [0.0] * width
            bias_gradient = 0.0
            for row, label in zip(features, labels, strict=True):
                value = sum(weight * feature for weight, feature in zip(weights, row, strict=True)) + bias
                probability = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, value))))
                error = probability - label
                for index in range(width):
                    gradient[index] += error * row[index]
                bias_gradient += error
            for index in range(width):
                weights[index] -= rate * gradient[index] / len(features)
            bias -= rate * bias_gradient / len(features)
        return {"weights": [round(value, 6) for value in weights], "bias": round(bias, 6)}

    def softmax(self, scores: Sequence[float], *, temperature: float = 1.0) -> list[float]:
        if not scores:
            raise AnswerError("no scores")
        highest = max(scores)
        exponentials = [math.exp((score - highest) / max(1e-6, temperature)) for score in scores]
        total = sum(exponentials) or 1.0
        return [value / total for value in exponentials]


def answer(question: str, passages: Sequence[dict[str, Any]], *, limit: int = 3) -> dict[str, Any]:
    started = time.perf_counter()
    evidence = Evidence(passages)
    ranked = evidence.bm25(question)
    if not ranked:
        return {
            "question": question,
            "answer": "No passage in the store matches the question.",
            "citations": [],
            "confidence": 0.0,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "method": "bm25 + softmax",
        }
    top = ranked[:limit]
    weights = evidence.softmax([row["score"] for row in top])
    text = " ".join(row["passage"]["text"] for row in top)
    citations = [
        {"title": row["passage"]["title"], "source": row["passage"]["source"], "score": row["score"], "weight": round(weight, 4)}
        for row, weight in zip(top, weights, strict=True)
    ]
    return {
        "question": question,
        "answer": text[:1200],
        "citations": citations,
        "confidence": round(sum(weights), 4),
        "top_score": top[0]["score"],
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "terms": tokenise(question),
        "method": "bm25 + softmax, extractive",
    }


def analyse(question: str, passages: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The full pipeline: matrix, equilibrium, gradient, answer."""
    evidence = Evidence(passages)
    matrix = evidence.tfidf_matrix()
    distribution = evidence.stationary(matrix)
    labels = [1 if row["score"] > 0 else 0 for row in evidence.bm25(question)]
    ranked = evidence.bm25(question)
    labels = [1] * len(ranked) + [0] * (len(evidence.passages) - len(ranked))
    features = matrix
    model = evidence.logistic(features, labels, epochs=60)
    return {
        "passages": len(evidence.passages),
        "vocabulary": len(evidence.vocabulary),
        "matrix_shape": [len(matrix), len(evidence.vocabulary)],
        "equilibrium_top": sorted(
            ({"passage": evidence.passages[index]["title"], "mass": round(value, 4)} for index, value in enumerate(distribution)),
            key=lambda row: -row["mass"],
        )[:3],
        "logistic": model,
        "answer": answer(question, passages),
    }
