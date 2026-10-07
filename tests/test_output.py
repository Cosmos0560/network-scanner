from __future__ import annotations

import json

from network_scanner.core.errors import NetErrorCode
from network_scanner.core.limits import DEFAULT_LIMITS
from network_scanner.core.model import (
    SCHEMA_VERSION,
    Family,
    PortResult,
    PortState,
    ResolvedTarget,
    ScanReport,
    TargetKind,
    TargetSpec,
)
from network_scanner.output.json_out import render_json
from network_scanner.output.table import render_table


def target(address: str, display: str | None = None) -> ResolvedTarget:
    family = Family.IPV6 if ":" in address else Family.IPV4
    return ResolvedTarget(display or address, address, family, TargetSpec(address, TargetKind.IP))


def result(
    address: str, port: int, state: PortState, code: NetErrorCode | None = None
) -> PortResult:
    return PortResult(address, port, state, code)


def report(
    results: list[PortResult], targets: list[ResolvedTarget], *, complete: bool = True
) -> ScanReport:
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version="1.2.3",
        started_at="2026-01-01T12:00:00+00:00",
        complete=complete,
        limits=DEFAULT_LIMITS,
        targets=tuple(targets),
        results=tuple(results),
        findings=(),
    )


MIXED = report(
    [
        result("10.0.0.1", 22, PortState.OPEN),
        result("10.0.0.1", 23, PortState.CLOSED, NetErrorCode.REFUSED),
        result("10.0.0.1", 445, PortState.FILTERED, NetErrorCode.TIMEOUT),
        result("10.0.0.2", 80, PortState.OPEN),
        result("10.0.0.2", 81, PortState.ERROR, NetErrorCode.RESET),
        result("10.0.0.2", 82, PortState.CLOSED, NetErrorCode.REFUSED),
    ],
    [target("10.0.0.1"), target("10.0.0.2", "lab.example")],
)


def test_the_table_lists_everything_but_closed_ports_and_counts_every_state() -> None:
    assert render_table(MIXED) == (
        "network-scanner 1.2.3  started 2026-01-01T12:00:00+00:00\n"
        "targets: 2  probes completed: 6\n"
        "\n"
        "ADDRESS                 PORT  STATE\n"
        "10.0.0.1                  22  open\n"
        "10.0.0.1                 445  filtered (timeout)\n"
        "lab.example (10.0.0.2)    80  open\n"
        "lab.example (10.0.0.2)    81  error (reset)\n"
        "\n"
        "open: 2  closed: 2  filtered: 1  error: 1\n"
    )


def test_a_partial_report_says_so() -> None:
    partial = report([result("10.0.0.1", 22, PortState.OPEN)], [target("10.0.0.1")], complete=False)
    text = render_table(partial)
    assert "INCOMPLETE: the scan stopped before every probe finished" in text.splitlines()


def test_a_table_with_nothing_to_list_says_so() -> None:
    quiet = report(
        [result("10.0.0.1", 22, PortState.CLOSED, NetErrorCode.REFUSED)], [target("10.0.0.1")]
    )
    text = render_table(quiet)
    assert "no open, filtered or error results" in text
    assert text.endswith("open: 0  closed: 1  filtered: 0  error: 0\n")


def test_an_empty_report_renders() -> None:
    text = render_table(report([], [], complete=False))
    assert text.endswith("open: 0  closed: 0  filtered: 0  error: 0\n")


def test_values_are_sanitised_even_though_they_are_safe_by_construction() -> None:
    hostile = target("10.0.0.1", "evil\x1b[31m\r\nname\u202e")
    text = render_table(report([result("10.0.0.1", 22, PortState.OPEN)], [hostile]))
    assert not any(c in text for c in "\x1b\r\u202e")
    assert text.isascii() or "evil" in text  # no crash; control characters are gone
    assert "\x1b" not in text


def test_the_table_is_ascii_only() -> None:
    assert render_table(MIXED).isascii()


def test_the_json_is_the_whole_report_in_model_order() -> None:
    text = render_json(MIXED)
    assert text.endswith("}\n")
    data = json.loads(text)
    assert list(data) == [
        "schema_version",
        "tool_version",
        "started_at",
        "complete",
        "limits",
        "targets",
        "results",
        "findings",
    ]
    assert data["results"][2] == {
        "address": "10.0.0.1",
        "port": 445,
        "state": "filtered",
        "error_code": "timeout",
    }
    assert data["targets"][1]["display_name"] == "lab.example"
    assert data["complete"] is True
    assert len(data["results"]) == 6


def test_the_json_is_ascii_even_if_a_name_is_not() -> None:
    odd = report([], [target("10.0.0.1", "b\u00fccher.example")])
    text = render_json(odd)
    assert text.isascii()
    assert json.loads(text)["targets"][0]["display_name"] == "b\u00fccher.example"


def test_the_same_report_renders_identically() -> None:
    assert render_json(MIXED) == render_json(MIXED)
    assert render_table(MIXED) == render_table(MIXED)
