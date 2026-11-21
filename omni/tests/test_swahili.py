import pytest

from omnishield.swahili import (
    SwahiliError,
    parse,
    swahili_reasoning,
    translate_connectives,
)


def test_parses_the_supported_swahili_patterns():
    assert parse("Kila mwanafunzi ni mwerevu")["kind"] == "all"
    assert parse("Hakuna ndege ni mdudu")["kind"] == "none"
    assert parse("Baadhi ya wanyama ni wakubwa")["kind"] == "some"
    assert parse("Juma ni mwanafunzi")["kind"] == "is"
    assert parse("Juma si mwalimu")["kind"] == "not"
    assert parse("Hii ni sentensi isiyojulikana kabisa")["kind"] in {"is", "unparsed"}
    with pytest.raises(SwahiliError):
        parse("   ")


def test_forward_chaining_proves_a_conclusion():
    result = swahili_reasoning(
        ["Kila mwanafunzi ni mwerevu", "Juma ni mwanafunzi"], "Juma ni mwerevu"
    )
    assert result["answer"] == "ndiyo"
    assert result["entailed"] is True
    assert result["proof"]
    assert result["unparsed"] == []


def test_none_rules_contradict_and_unknowns_stay_unknown():
    blocked = swahili_reasoning(["Hakuna ndege ni mdudu", "Kuku ni ndege"], "Kuku ni mdudu")
    assert blocked["answer"] == "hapana"
    assert blocked["contradicted"] is True
    assert swahili_reasoning(["Kila mwanafunzi ni mwerevu"], "Juma ni mwerevu")["answer"] == "sijui"


def test_transitive_rules_and_connective_translation():
    result = swahili_reasoning(
        ["Kila paka ni mnyama", "Kila mnyama ni kiumbe"], "paka ni kiumbe"
    )
    assert result["answer"] == "ndiyo"
    assert translate_connectives("Kama mvua na baridi, kwa hiyo tutakaa ndani") == (
        "if mvua and baridi therefore tutakaa ndani"
    )
    with pytest.raises(SwahiliError):
        swahili_reasoning([], "Juma ni mwerevu")
