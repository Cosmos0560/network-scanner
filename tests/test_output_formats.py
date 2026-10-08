"""The four report formats, with services, TLS facts and findings, and the injection suite."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import replace
from typing import Any

import pytest

from network_scanner.core.errors import NetErrorCode
from network_scanner.core.limits import DEFAULT_LIMITS, MAX_OUTPUT_STRING_CHARS
from network_scanner.core.model import (
    SCHEMA_VERSION,
    Baseline,
    BaselineEntry,
    Confidence,
    Drift,
    Family,
    Finding,
    Observation,
    PortObservation,
    PortResult,
    PortState,
    ResolvedTarget,
    ScanReport,
    Service,
    Severity,
    TargetKind,
    TargetSpec,
    TlsInfo,
)
from network_scanner.output.csv_out import COLUMNS, FORMULA_STARTS, neutralise, render_csv
from network_scanner.output.drift import render_drift_json, render_drift_table
from network_scanner.output.json_out import render_json
from network_scanner.output.jsonl import render_jsonl
from network_scanner.output.table import render_table

SPEC = TargetSpec("10.0.0.5", TargetKind.IP)
TARGET = ResolvedTarget("10.0.0.5", "10.0.0.5", Family.IPV4, SPEC)


def tls_info(**changes: Any) -> TlsInfo:
    base = TlsInfo(
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        subject="CN=lab.test",
        issuer="CN=lab.test",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        san=("DNS:lab.test", "IP:10.0.0.5"),
        san_truncated=False,
        sha256="ab" * 32,
        self_issued=True,
        self_signature_valid=True,
        expired=False,
        hostname_match=None,
        parse_error=None,
    )
    return replace(base, **changes)


def make_report(
    *,
    results: list[PortResult],
    observations: list[PortObservation],
    findings: list[Finding],
    probed: bool = True,
) -> ScanReport:
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version="1.2.3",
        started_at="2026-01-01T12:00:00+00:00",
        complete=True,
        probed=probed,
        limits=DEFAULT_LIMITS,
        targets=(TARGET,),
        results=tuple(results),
        observations=tuple(observations),
        findings=tuple(findings),
    )


SSH = PortObservation(
    "10.0.0.5",
    22,
    Observation("SSH-2.0-Lab_1.0", False, "banner", None, None, None),
    Service("ssh", "ssh-identification", Confidence.HIGH),
)
WEB = PortObservation(
    "10.0.0.5",
    80,
    Observation(None, False, "http_head", 200, "Lab/1.0", None),
    Service("http", "http-status-line", Confidence.HIGH),
)
TLS = PortObservation(
    "10.0.0.5",
    443,
    Observation(None, False, "tls", None, None, tls_info()),
    Service("tls", "tls-handshake", Confidence.HIGH),
)
FINDING = Finding(
    id="tls-certificate-self-issued",
    title="Certificate is self-issued (issuer equals subject)",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    address="10.0.0.5",
    port=443,
    evidence="10.0.0.5:443 subject CN=lab.test, issuer CN=lab.test",
    references=("RFC 5280",),
)
TELNET_FINDING = Finding(
    id="cleartext-telnet",
    title="Telnet service",
    severity=Severity.MEDIUM,
    confidence=Confidence.LOW,
    address="10.0.0.5",
    port=23,
    evidence="10.0.0.5:23 looks like telnet",
    references=("CWE-319", "RFC 854"),
)
RICH = make_report(
    results=[
        PortResult("10.0.0.5", 22, PortState.OPEN, None),
        PortResult("10.0.0.5", 23, PortState.CLOSED, NetErrorCode.REFUSED),
        PortResult("10.0.0.5", 80, PortState.OPEN, None),
        PortResult("10.0.0.5", 443, PortState.OPEN, None),
        PortResult("10.0.0.5", 445, PortState.FILTERED, NetErrorCode.TIMEOUT),
    ],
    observations=[SSH, WEB, TLS],
    findings=[FINDING, TELNET_FINDING],
)


# -- the table -------------------------------------------------------------------------------


def test_the_table_shows_services_details_and_findings_most_severe_first() -> None:
    assert render_table(RICH) == (
        "network-scanner 1.2.3  started 2026-01-01T12:00:00+00:00\n"
        "targets: 1  probes completed: 5\n"
        "\n"
        "ADDRESS   PORT  STATE               SERVICE\n"
        "10.0.0.5    22  open                ssh (high)\n"
        "10.0.0.5    80  open                http (high)\n"
        "10.0.0.5   443  open                tls (high)\n"
        "10.0.0.5   445  filtered (timeout)  -\n"
        "\n"
        "PORT DETAILS\n"
        "10.0.0.5:22\n"
        "  banner: SSH-2.0-Lab_1.0\n"
        "10.0.0.5:80\n"
        "  http: status 200, server Lab/1.0\n"
        "10.0.0.5:443\n"
        "  tls: TLSv1.3, cipher TLS_AES_256_GCM_SHA384\n"
        "  certificate: subject CN=lab.test; issuer CN=lab.test\n"
        "  validity: 2026-01-01T00:00:00+00:00 to 2027-01-01T00:00:00+00:00; expired no\n"
        "  names: DNS:lab.test, IP:10.0.0.5\n"
        "  facts: self-issued yes; signature verifies under own key yes; "
        "host name matches unknown\n"
        f"  sha256: {'ab' * 32}\n"
        "\n"
        "FINDINGS\n"
        "[medium/low] cleartext-telnet 10.0.0.5:23 - Telnet service\n"
        "    evidence: 10.0.0.5:23 looks like telnet\n"
        "    references: CWE-319, RFC 854\n"
        "[info/high] tls-certificate-self-issued 10.0.0.5:443 - "
        "Certificate is self-issued (issuer equals subject)\n"
        "    evidence: 10.0.0.5:443 subject CN=lab.test, issuer CN=lab.test\n"
        "    references: RFC 5280\n"
        "\n"
        "open: 3  closed: 1  filtered: 1  error: 0\n"
        "findings: 2 (medium: 1, info: 1)\n"
    )


def test_a_connect_only_table_has_no_service_column_and_no_findings_line() -> None:
    plain = make_report(
        results=[PortResult("10.0.0.5", 22, PortState.OPEN, None)],
        observations=[],
        findings=[],
        probed=False,
    )
    text = render_table(plain)
    assert "SERVICE" not in text
    assert "findings:" not in text
    assert "PORT DETAILS" not in text


def test_a_certificate_that_could_not_be_read_is_said_so() -> None:
    broken = PortObservation(
        "10.0.0.5",
        443,
        Observation(None, False, "tls", None, None, tls_info(parse_error="malformed_certificate")),
        None,
    )
    text = render_table(make_report(results=[], observations=[broken], findings=[]))
    assert "  certificate not read: malformed_certificate\n" in text
    assert "certificate: subject" not in text


def test_a_cut_banner_and_a_cut_name_list_are_marked() -> None:
    cut = PortObservation(
        "10.0.0.5",
        1,
        Observation("long...", True, "banner", None, None, tls_info(san_truncated=True)),
        None,
    )
    text = render_table(make_report(results=[], observations=[cut], findings=[]))
    assert "  banner: long... (cut)\n" in text
    assert "  names: DNS:lab.test, IP:10.0.0.5, ...\n" in text


# -- JSON and JSON Lines ---------------------------------------------------------------------


def test_json_carries_services_observations_and_findings() -> None:
    data = json.loads(render_json(RICH))
    assert data["probed"] is True
    assert [(o["port"], o["service"]["name"]) for o in data["observations"]] == [
        (22, "ssh"),
        (80, "http"),
        (443, "tls"),
    ]
    tls = data["observations"][2]["observation"]["tls"]
    assert (tls["version"], tls["self_issued"], tls["self_signature_valid"]) == (
        "TLSv1.3",
        True,
        True,
    )
    assert data["observations"][0]["observation"]["banner"] == "SSH-2.0-Lab_1.0"
    assert [f["id"] for f in data["findings"]] == [FINDING.id, TELNET_FINDING.id]
    assert data["findings"][0]["severity"] == "info"
    assert data["findings"][0]["confidence"] == "high"
    assert data["findings"][1]["references"] == ["CWE-319", "RFC 854"]


def test_jsonl_has_one_typed_object_per_line_in_a_fixed_order() -> None:
    text = render_jsonl(RICH)
    assert text.endswith("\n")
    lines = text.splitlines()
    objects = [json.loads(line) for line in lines]
    assert [o["type"] for o in objects] == [
        "scan",
        "target",
        "result",
        "result",
        "result",
        "result",
        "result",
        "observation",
        "observation",
        "observation",
        "finding",
        "finding",
    ]
    assert all(next(iter(o)) == "type" for o in objects)
    assert objects[0]["probed"] is True
    assert objects[0]["limits"]["concurrency"] == DEFAULT_LIMITS.concurrency
    assert objects[7]["service"]["rule_id"] == "ssh-identification"
    assert objects[9]["observation"]["tls"]["sha256"] == "ab" * 32
    assert objects[-1]["id"] == TELNET_FINDING.id
    assert text.isascii()


def test_a_report_with_nothing_in_it_still_renders_in_every_format() -> None:
    empty = make_report(results=[], observations=[], findings=[], probed=False)
    assert json.loads(render_json(empty))["observations"] == []
    assert [json.loads(line)["type"] for line in render_jsonl(empty).splitlines()] == [
        "scan",
        "target",
    ]
    assert render_csv(empty).splitlines() == ['"' + '","'.join(COLUMNS) + '"']
    assert "no open, filtered or error results" in render_table(empty)


# -- CSV -------------------------------------------------------------------------------------


def rows_of(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def test_csv_has_a_header_port_rows_and_finding_rows() -> None:
    text = render_csv(RICH)
    assert text.splitlines()[0] == '"' + '","'.join(COLUMNS) + '"'
    rows = rows_of(text)
    assert [r["record"] for r in rows] == ["port"] * 5 + ["finding"] * 2
    ssh, closed, web, tls, filtered = rows[:5]
    assert (ssh["address"], ssh["port"], ssh["state"], ssh["service"]) == (
        "10.0.0.5",
        "22",
        "open",
        "ssh",
    )
    assert (ssh["service_confidence"], ssh["service_rule"], ssh["banner"]) == (
        "high",
        "ssh-identification",
        "SSH-2.0-Lab_1.0",
    )
    assert (closed["state"], closed["error_code"], closed["service"]) == ("closed", "refused", "")
    assert (web["http_status"], web["http_server"], web["probe"]) == ("200", "Lab/1.0", "http_head")
    assert (tls["tls_version"], tls["tls_self_issued"], tls["tls_hostname_match"]) == (
        "TLSv1.3",
        "true",
        "",
    )
    assert tls["tls_san"] == "DNS:lab.test; IP:10.0.0.5"
    assert (filtered["state"], filtered["error_code"]) == ("filtered", "timeout")
    finding = rows[5]
    assert (finding["finding_id"], finding["severity"], finding["confidence"]) == (
        FINDING.id,
        "info",
        "high",
    )
    assert finding["references"] == "RFC 5280"
    assert rows[6]["references"] == "CWE-319; RFC 854"
    assert finding["evidence"] == FINDING.evidence


def test_csv_numbers_are_unquoted_and_text_is_quoted() -> None:
    line = render_csv(RICH).splitlines()[1]
    assert line.startswith('"port","10.0.0.5",22,"open"')


@pytest.mark.parametrize("start", FORMULA_STARTS, ids=["eq", "plus", "minus", "at", "tab", "cr"])
def test_cells_starting_with_a_formula_character_are_defused(start: str) -> None:
    value = start + "cmd|' /C calc'!A0"
    assert neutralise(value).startswith("'")
    banner = PortObservation(
        "10.0.0.5", 9, Observation(value, False, "banner", None, None, None), None
    )
    report = make_report(
        results=[PortResult("10.0.0.5", 9, PortState.OPEN, None)],
        observations=[banner],
        findings=[],
    )
    [row] = rows_of(render_csv(report))
    assert row["banner"].startswith("'")
    assert not row["banner"].lstrip("'").startswith("\r")


@pytest.mark.parametrize(
    "value",
    [
        "=1+1",
        "+1",
        "-1",
        "@SUM(A1)",
        "\t=1+1",
        "\r=1+1",
        " =1+1",
        "  @x",
        '=HYPERLINK("http://x","y")',
    ],
)
def test_a_formula_is_never_the_first_visible_thing_in_a_cell(value: str) -> None:
    cell = neutralise(value)
    assert cell.startswith("'")
    assert not cell.lstrip(" ").startswith(FORMULA_STARTS)


@pytest.mark.parametrize("value", ["plain", "a=b", "x+y", "ssh-2.0", "", "1+1", "::1", "'quoted"])
def test_ordinary_cells_are_left_alone(value: str) -> None:
    assert neutralise(value) == value


def test_every_cell_of_every_row_is_safe_when_every_text_field_is_hostile() -> None:
    hostile = "=cmd|' /C calc'!A0"
    report = hostile_report(hostile)
    for row in rows_of(render_csv(report)):
        for column, cell in row.items():
            assert not cell.startswith(FORMULA_STARTS), (column, cell)


# -- the injection suite: every format, every network-sourced field --------------------------

NASTY = (
    "a\x1b[31mRED\x1b[0m\x1b]0;title\x07\x00\x01\x7f\u202e\u200b\u2066x\r\nFAKE: line\n"
    '"quote",comma\x0b\x0c' + "z" * 30
)


def hostile_report(text: str) -> ScanReport:
    tls = tls_info(
        version=text,
        cipher=text,
        subject=text,
        issuer=text,
        not_before=text,
        not_after=text,
        san=(text, text),
        sha256=text,
        parse_error=None,
    )
    observation = PortObservation(
        text,
        8,
        Observation(text, True, text, 200, text, tls),
        Service(text, text, Confidence.HIGH),
    )
    finding = Finding(
        id=text,
        title=text,
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        address=text,
        port=8,
        evidence=text,
        references=(text,),
    )
    return replace(
        make_report(
            results=[PortResult(text, 8, PortState.OPEN, None)],
            observations=[replace(observation, address=text)],
            findings=[finding],
        ),
        targets=(ResolvedTarget(text, text, Family.IPV4, TargetSpec(text, TargetKind.HOSTNAME)),),
    )


FORBIDDEN = ("\x1b", "\x07", "\x00", "\x01", "\x7f", "\u202e", "\u200b", "\u2066", "\x0b", "\x0c")


def assert_clean(text: str, *, allow_newline: bool = True) -> None:
    for char in FORBIDDEN:
        assert char not in text, repr(char)
    assert "\r" not in text
    if not allow_newline:
        assert "\n" not in text


def strings_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*strings_in(k), *strings_in(v))]
    if isinstance(value, list):
        return [s for item in value for s in strings_in(item)]
    return []


def test_json_strings_are_all_clean_and_the_output_is_ascii() -> None:
    text = render_json(hostile_report(NASTY))
    assert text.isascii()
    for string in strings_in(json.loads(text)):
        assert_clean(string, allow_newline=False)
    assert "FAKE: line" in text  # the words survive; only their power to start a line is gone


def test_jsonl_hostile_text_cannot_add_lines_or_survive() -> None:
    text = render_jsonl(hostile_report(NASTY))
    assert text.isascii()
    lines = text.splitlines()
    assert len(lines) == 5  # scan, target, result, observation, finding: nothing more
    assert text.count("\n") == len(lines)
    for line in lines:
        for string in strings_in(json.loads(line)):
            assert_clean(string, allow_newline=False)


def test_csv_hostile_text_cannot_add_rows_or_columns() -> None:
    text = render_csv(hostile_report(NASTY))
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert len(rows) == 1 + 1 + 1  # header, the one port row, the one finding row
    assert all(len(row) == len(COLUMNS) for row in rows)
    assert_clean(text)
    assert text.count("\n") == len(rows)  # every line break is a row break


def test_table_hostile_text_cannot_add_lines_or_survive() -> None:
    benign = render_table(hostile_report("benign"))
    nasty = render_table(hostile_report(NASTY))
    assert nasty.isascii()
    assert_clean(nasty)
    assert len(nasty.splitlines()) == len(benign.splitlines())


@pytest.mark.parametrize("renderer", [render_json, render_jsonl, render_csv, render_table])
def test_a_huge_string_is_cut_in_every_format(renderer: Any) -> None:
    out = renderer(hostile_report("q" * (MAX_OUTPUT_STRING_CHARS * 5)))
    assert "q" * (MAX_OUTPUT_STRING_CHARS + 1) not in out
    assert len(out) < MAX_OUTPUT_STRING_CHARS * 60


@pytest.mark.parametrize("renderer", [render_json, render_jsonl, render_csv, render_table])
def test_non_ascii_text_is_kept_in_the_data_and_the_ascii_formats_stay_ascii(renderer: Any) -> None:
    report = hostile_report("café 日本")
    out = renderer(report)
    if renderer in (render_json, render_jsonl, render_table):
        assert out.isascii() or renderer is render_table
    if renderer is render_json:
        assert "caf\\u00e9" in out


# -- drift -----------------------------------------------------------------------------------


def entry(address: str, port: int, service: str | None) -> BaselineEntry:
    return BaselineEntry(address, port, service)


DRIFT = Drift(
    new=(entry("10.0.0.1", 9000, "ssh"),),
    closed=(entry("10.0.0.1", 443, "tls"),),
    changed=((entry("10.0.0.1", 80, "http"), entry("10.0.0.1", 80, None)),),
    not_scanned=(entry("10.0.0.9", 22, "ssh"),),
)


def test_the_drift_table_lists_every_entry() -> None:
    assert render_drift_table(DRIFT) == (
        "baseline diff: drift found\n"
        "new: 1  closed: 1  changed: 1  not scanned: 1\n"
        "\n"
        "NEW          10.0.0.1:9000 (ssh)\n"
        "CLOSED       10.0.0.1:443 (tls)\n"
        "CHANGED      10.0.0.1:80 http -> unidentified\n"
        "NOT SCANNED  10.0.0.9:22 (ssh)\n"
    )


def test_the_drift_table_with_nothing_to_report_and_with_findings() -> None:
    empty = Drift((), (), (), ())
    assert render_drift_table(empty) == (
        "baseline diff: no drift\nnew: 0  closed: 0  changed: 0  not scanned: 0\n"
    )
    text = render_drift_table(empty, (TELNET_FINDING, FINDING))
    assert "findings in this scan: 2 (medium: 1, info: 1)" in text
    assert text.index("cleartext-telnet") < text.index("tls-certificate-self-issued")


def test_the_drift_json_has_the_flag_the_lists_and_the_findings() -> None:
    data = json.loads(render_drift_json(DRIFT, (FINDING,)))
    assert data["has_drift"] is True
    assert data["drift"]["new"] == [{"address": "10.0.0.1", "port": 9000, "service": "ssh"}]
    assert data["drift"]["changed"][0][1]["service"] is None
    assert data["drift"]["not_scanned"][0]["port"] == 22
    assert data["findings"][0]["id"] == FINDING.id
    quiet = json.loads(render_drift_json(Drift((), (), (), ())))
    assert quiet["has_drift"] is False
    assert quiet["findings"] == []


def test_drift_output_is_sanitised() -> None:
    hostile = Drift(new=(entry("a\x1b[31m\u202e", 1, "x"),), closed=(), changed=(), not_scanned=())
    for text in (render_drift_table(hostile), render_drift_json(hostile)):
        assert_clean(text)


def test_a_baseline_value_is_still_a_plain_model_value() -> None:
    assert Baseline(SCHEMA_VERSION, "t", ()).entries == ()
