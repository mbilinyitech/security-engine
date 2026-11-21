import json

import pytest

from omnishield.corpus import (
    CorpusError,
    learn_book,
    learn_dictionary,
    learn_directory,
    paragraphs,
    read_dictionary,
)
from omnishield.knowledge import KnowledgeStore
from omnishield.omnilang import Lexicon


def test_dictionary_and_book_are_learned(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    lexicon = Lexicon(tmp_path / "lex.json")
    dictionary = tmp_path / "mini.dict"
    dictionary.write_text("habari = greeting\nmaji: water\n", encoding="utf-8")
    entries = learn_dictionary(store, lexicon, dictionary)
    assert entries["entries"] == 2
    assert entries["new_roots"] == 2
    book = tmp_path / "book.txt"
    book.write_text("The path tracer bounces light between surfaces. " * 8, encoding="utf-8")
    pages = learn_book(store, lexicon, book)
    assert pages["passages"] == 1
    assert pages["words"] > 20
    assert pages["lexicon"] > 2
    assert len(store.items) == 3


def test_jsonl_dictionary_and_directory(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    lexicon = Lexicon(tmp_path / "lex.json")
    path = tmp_path / "words.jsonl"
    path.write_text(json.dumps({"word": "sun", "definition": "the star of the day"}) + "\n", encoding="utf-8")
    assert read_dictionary(path)[0]["word"] == "sun"
    (tmp_path / "book.txt").write_text("A long paragraph about light and colour and shadow. " * 5, encoding="utf-8")
    report = learn_directory(store, lexicon, tmp_path)
    assert report["entries"] == 1
    assert report["passages"] == 1
    assert report["errors"] == []


def test_errors_are_refused(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    lexicon = Lexicon(tmp_path / "lex.json")
    with pytest.raises(CorpusError):
        learn_book(store, lexicon, tmp_path / "missing.txt")
    empty = tmp_path / "empty.txt"
    empty.write_text("short\n\nshort", encoding="utf-8")
    with pytest.raises(CorpusError):
        learn_book(store, lexicon, empty)
    bad = tmp_path / "bad.dict"
    bad.write_text("no pairs here", encoding="utf-8")
    with pytest.raises(CorpusError):
        learn_dictionary(store, lexicon, bad)
    with pytest.raises(CorpusError):
        learn_directory(store, lexicon, tmp_path / "nope")
    assert paragraphs("x" * 50 + "\n\n" + "y" * 150) == ["y" * 150]
