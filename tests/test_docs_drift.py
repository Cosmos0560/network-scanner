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


def test_performance_doc_names_the_default_timeout_it_was_measured_against() -> None:
    text = " ".join(read("performance.md").split())
    assert f"connect timeout in the code at the time | {DEFAULT_LIMITS.connect_timeout_s} s" in text


def test_measured_numbers_appear_only_in_the_performance_doc() -> None:
    readme = (DOCS.parent / "README.md").read_text(encoding="utf-8")
    others = {path.name: path.read_text(encoding="utf-8") for path in DOCS.glob("*.md")}
    others["README.md"] = readme
    del others["performance.md"]
    pattern = re.compile(
        r"\b\d+(\.\d+)?\s?(ms|milliseconds)\b|\bmedian\b|\b\d+\s+tests?\b|\bcoverage\b.*\d+\s?%"
    )
    offenders = {
        name: pattern.findall(text) for name, text in others.items() if pattern.search(text)
    }
    assert offenders == {}


PHASE4_LIMITS = (
    "MAX_BANNER_CHARS",
    "HTTP_HEAD_TIMEOUT_S",
    "MAX_HTTP_HEAD_BYTES",
    "MAX_HTTP_HEADER_LINES",
    "MAX_HTTP_SERVER_CHARS",
    "TLS_HANDSHAKE_TIMEOUT_S",
    "CLOSE_TIMEOUT_S",
    "ABORT_GRACE_S",
    "MAX_CERT_DER_BYTES",
    "MAX_CERT_FIELD_CHARS",
    "MAX_SAN_ENTRIES",
    "MAX_RULE_FILE_BYTES",
    "MAX_RULES",
    "MAX_RULE_FILES",
    "MAX_REGEX_PATTERN_CHARS",
    "MAX_REGEX_INPUT_CHARS",
    "MAX_REGEX_REPEAT",
    "MAX_REGEX_COST",
    "MAX_REGEX_GROUP_DEPTH",
    "MAX_EVIDENCE_CHARS",
    "MAX_BASELINE_BYTES",
    "MAX_BASELINE_ENTRIES",
    "MAX_OUTPUT_STRING_CHARS",
)


def test_the_probe_limits_table_matches_core_limits() -> None:
    from network_scanner.core import limits

    table = generated(read("architecture.md"), "probe_limits")
    rows = re.findall(r"^\| `([A-Z_]+)` \| ([0-9.]+) \|", table, flags=re.MULTILINE)
    assert [name for name, _ in rows] == list(PHASE4_LIMITS)
    for name, shown in rows:
        value = getattr(limits, name)
        assert float(shown) == float(value), name


def test_every_fixed_bound_in_core_limits_is_either_documented_or_listed_as_older() -> None:
    """A new fixed bound cannot be added to core/limits.py without a decision about the docs."""
    from network_scanner.core import limits

    older = {
        "MAX_TARGET_CHARS",
        "MAX_DNS_ANSWERS",
        "RESOLVE_TIMEOUT_S",
        "MAX_SCOPE_FILE_BYTES",
        "MAX_SCOPE_ENTRIES",
        "MAX_PORT_SPEC_CHARS",
        "MAX_PROBES_PER_RUN",
    }
    constants = {
        name
        for name, value in vars(limits).items()
        if name.isupper() and isinstance(value, int | float) and name not in {"CEILINGS"}
    }
    assert constants - older - set(PHASE4_LIMITS) == set()


def test_the_documented_probe_defaults_match_the_run_limits() -> None:
    text = " ".join(read("architecture.md").split())
    assert "`probes_per_open_port` (3 at most" in text
    assert DEFAULT_LIMITS.probes_per_open_port == CEILINGS["probes_per_open_port"] == 3
