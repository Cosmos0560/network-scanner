"""Generated tables and documented numbers must match the code they describe."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from network_scanner.core.errors import ReasonCode
from network_scanner.core.limits import (
    CEILINGS,
    DEFAULT_LIMITS,
    MAX_DNS_ANSWERS,
    MAX_PORT_SPEC_CHARS,
    MAX_SCOPE_ENTRIES,
    MAX_SCOPE_FILE_BYTES,
    MAX_TARGET_CHARS,
    RESOLVE_TIMEOUT_S,
)
from network_scanner.ports.presets import load_preset, render_markdown_table
from network_scanner.scope.classify import table_markdown

DOCS = Path(__file__).resolve().parent.parent / "docs"


def read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def generated(document: str, name: str) -> str:
    begin, end = f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->"
    assert document.count(begin) == 1, f"{name}: expected exactly one begin marker"
    assert document.count(end) == 1, f"{name}: expected exactly one end marker"
    return document.split(begin, 1)[1].split(end, 1)[0].strip("\n")


def test_the_ports_table_matches_the_preset_file() -> None:
    expected = render_markdown_table(load_preset("common"))
    assert generated(read("ports.md"), "ports_common") == expected


def test_the_address_class_table_matches_the_classifier_tables() -> None:
    assert generated(read("scope-policy.md"), "scope_classes") == table_markdown()


def test_every_reason_code_is_documented_exactly_once() -> None:
    section = read("scope-policy.md").split("## Reason codes", 1)[1].split("\n## ", 1)[0]
    documented = re.findall(r"^\| `([a-z0-9_]+)` \|", section, flags=re.MULTILINE)
    assert sorted(documented) == sorted(code.value for code in ReasonCode)


@pytest.mark.parametrize(
    "phrase",
    [
        f"({DEFAULT_LIMITS.max_targets} by default, never more than {CEILINGS['max_targets']})",
        f"A target is at most {MAX_TARGET_CHARS} characters",
        f"({RESOLVE_TIMEOUT_S:g} s timeout, at most {MAX_DNS_ANSWERS} answers)",
        f"at most {MAX_SCOPE_FILE_BYTES // 1024} KB and {MAX_SCOPE_ENTRIES} entries",
    ],
)
def test_documented_scope_numbers_match_the_constants(phrase: str) -> None:
    text = " ".join(read("scope-policy.md").split())
    assert phrase in text


def test_documented_port_numbers_match_the_constants() -> None:
    text = " ".join(read("ports.md").split())
    default, ceiling = DEFAULT_LIMITS.max_ports_per_target, CEILINGS["max_ports_per_target"]
    assert f"({default} by default, never more than {ceiling})" in text
    assert f"at most {MAX_PORT_SPEC_CHARS} characters" in text
