from __future__ import annotations

import pytest

from network_scanner.core.yamlsafe import MAX_YAML_DEPTH, safe_load_document


class DataError(Exception):
    pass


def load(text: str) -> object:
    return safe_load_document(text, error=DataError)


def test_a_plain_document_loads() -> None:
    assert load("a: 1\nb: [x, y]\n") == {"a": 1, "b": ["x", "y"]}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: &x 1\nb: *x\n", "anchors"),
        ("a: *x\n", "aliases"),
        ("a: !!python/object/apply:os.system ['echo']\n", "explicit tags"),
        ("a: 1\na: 2\n", "duplicate key 'a'"),
        ("? [a]\n: b\n", "plain scalars"),
        ("[" * (MAX_YAML_DEPTH + 2) + "]" * (MAX_YAML_DEPTH + 2), "nested too deeply"),
        ("a: [", "invalid YAML (ParserError)"),
    ],
)
def test_forbidden_features_are_reported_through_the_callers_error(text: str, message: str) -> None:
    with pytest.raises(DataError, match=message.replace("(", r"\(").replace(")", r"\)")):
        load(text)
