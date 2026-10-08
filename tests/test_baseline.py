"""The baseline file (strict, untrusted on the way back in) and the comparison of scans."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from network_scanner.baseline import store
from network_scanner.baseline.diff import diff_baselines, has_drift
from network_scanner.baseline.store import (
    BASELINE_KIND,
    BaselineError,
    build_baseline,
    load_baseline,
    parse_baseline,
    render_baseline,
)
from network_scanner.core.errors import NetErrorCode
from network_scanner.core.limits import (
    DEFAULT_LIMITS,
    MAX_BASELINE_BYTES,
    MAX_BASELINE_ENTRIES,
    MAX_PROBES_PER_RUN,
)
from network_scanner.core.model import (
    SCHEMA_VERSION,
    Baseline,
    BaselineEntry,
    Confidence,
    Observation,
    PortObservation,
    PortResult,
    PortState,
    ScanReport,
    Service,
)

CREATED = "2026-01-01T12:00:00+00:00"


def open_result(address: str, port: int) -> PortResult:
    return PortResult(address, port, PortState.OPEN, None)


def observed(address: str, port: int, service: str | None) -> PortObservation:
    found = None if service is None else Service(service, f"{service}-rule", Confidence.HIGH)
    return PortObservation(address, port, Observation(None, False, None, None, None, None), found)


def report(
    results: list[PortResult],
    observations: list[PortObservation],
    *,
    complete: bool = True,
    probed: bool = True,
) -> ScanReport:
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version="1.2.3",
        started_at=CREATED,
        complete=complete,
        probed=probed,
        limits=DEFAULT_LIMITS,
        targets=(),
        results=tuple(results),
        observations=tuple(observations),
        findings=(),
    )


# -- building and writing --------------------------------------------------------------------


def test_a_baseline_holds_the_open_ports_with_their_services_in_address_order() -> None:
    scan = report(
        [
            open_result("10.0.0.10", 22),
            PortResult("10.0.0.10", 23, PortState.CLOSED, NetErrorCode.REFUSED),
            open_result("10.0.0.2", 443),
            open_result("10.0.0.2", 80),
            PortResult("10.0.0.2", 81, PortState.FILTERED, NetErrorCode.TIMEOUT),
            open_result("::1", 22),
            open_result("fe80::1%eth0", 22),
        ],
        [
            observed("10.0.0.10", 22, "ssh"),
            observed("10.0.0.2", 443, "tls"),
            observed("10.0.0.2", 80, None),
            observed("::1", 22, "ssh"),
            observed("fe80::1%eth0", 22, "ssh"),
        ],
    )
    baseline = build_baseline(scan)
    assert baseline.created_at == CREATED
    assert [(e.address, e.port, e.service) for e in baseline.entries] == [
        ("10.0.0.2", 80, None),
        ("10.0.0.2", 443, "tls"),
        ("10.0.0.10", 22, "ssh"),
        ("::1", 22, "ssh"),
        ("fe80::1%eth0", 22, "ssh"),
    ]


def test_a_partial_or_connect_only_scan_cannot_become_a_baseline() -> None:
    with pytest.raises(BaselineError, match="not complete"):
        build_baseline(report([], [], complete=False))
    with pytest.raises(BaselineError, match="connect-only"):
        build_baseline(report([], [], probed=False))


def test_the_rendered_baseline_is_exact_and_reads_back_to_the_same_value() -> None:
    baseline = Baseline(
        SCHEMA_VERSION,
        CREATED,
        (BaselineEntry("10.0.0.1", 22, "ssh"), BaselineEntry("10.0.0.1", 80, None)),
    )
    text = render_baseline(baseline)
    assert text == (
        "{\n"
        '  "schema_version": 1,\n'
        f'  "kind": "{BASELINE_KIND}",\n'
        f'  "created_at": "{CREATED}",\n'
        '  "entries": [\n'
        '    {\n      "address": "10.0.0.1",\n      "port": 22,\n      "service": "ssh"\n    },\n'
        '    {\n      "address": "10.0.0.1",\n      "port": 80,\n      "service": null\n    }\n'
        "  ]\n"
        "}\n"
    )
    assert parse_baseline(text.encode("utf-8")) == baseline
    assert render_baseline(parse_baseline(text.encode("utf-8"))) == text


# -- reading is strict -----------------------------------------------------------------------


def document(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "kind": BASELINE_KIND,
        "created_at": CREATED,
        "entries": [{"address": "10.0.0.1", "port": 22, "service": "ssh"}],
    }
    base.update(changes)
    return base


def parse(value: Any) -> Baseline:
    return parse_baseline(json.dumps(value).encode("utf-8"))


def entry(**changes: Any) -> dict[str, Any]:
    return {"address": "10.0.0.1", "port": 22, "service": "ssh", **changes}


BAD_DOCUMENTS = [
    ([], "baseline: expected an object"),
    ("text", "baseline: expected an object"),
    (document(extra=1), "unknown key 'extra'"),
    ({k: v for k, v in document().items() if k != "kind"}, "missing key 'kind'"),
    ({k: v for k, v in document().items() if k != "entries"}, "missing key 'entries'"),
    (document(kind="something-else"), "not a baseline file"),
    (document(schema_version=2), "written by a newer network-scanner"),
    (document(schema_version=99), "newer network-scanner"),
    (document(schema_version=0), "not supported"),
    (document(schema_version="1"), "schema_version: expected a whole number"),
    (document(schema_version=True), "schema_version: expected a whole number"),
    (document(created_at=5), "created_at"),
    (document(created_at="yesterday"), "created_at"),
    (document(created_at="2026-01-01T12:00:00+00:00\nX"), "created_at"),
    (document(entries={}), "entries: expected a list"),
    (document(entries=[1]), "entries[0]: expected an object"),
    (document(entries=[entry(extra=1)]), "entries[0]: unknown key 'extra'"),
    (document(entries=[{"address": "10.0.0.1", "port": 22}]), "missing key 'service'"),
    (document(entries=[entry(address=5)]), "entries[0].address"),
    (document(entries=[entry(address="example.test")]), "entries[0].address: invalid_target"),
    (document(entries=[entry(address="0x7f.0.0.1")]), "entries[0].address: ambiguous_numeric"),
    (document(entries=[entry(address="10.0.0.0/24")]), "entries[0].address"),
    (document(entries=[entry(address="1" * 65)]), "entries[0].address"),
    (document(entries=[entry(port=0)]), "entries[0].port"),
    (document(entries=[entry(port=65536)]), "entries[0].port"),
    (document(entries=[entry(port=-1)]), "entries[0].port"),
    (document(entries=[entry(port="22")]), "entries[0].port"),
    (document(entries=[entry(port=True)]), "entries[0].port"),
    (document(entries=[entry(service="SSH")]), "entries[0].service"),
    (document(entries=[entry(service=5)]), "entries[0].service"),
    (document(entries=[entry(service="")]), "entries[0].service"),
    (document(entries=[entry(service="a" * 33)]), "entries[0].service"),
    (document(entries=[entry(), entry()]), "entries[1]: the same address and port as entries[0]"),
    (
        document(entries=[entry(address="::1"), entry(address="0:0:0:0:0:0:0:1")]),
        "same address and port as entries[0]",
    ),
]


@pytest.mark.parametrize(
    ("value", "message"),
    BAD_DOCUMENTS,
    ids=[f"{n}-{m[:30]}" for n, (_, m) in enumerate(BAD_DOCUMENTS)],
)
def test_unexpected_content_is_refused_with_a_clear_message(value: Any, message: str) -> None:
    with pytest.raises(BaselineError) as caught:
        parse(value)
    assert message in str(caught.value)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff\xfe\x00", "not valid UTF-8"),
        (b"", "not valid JSON"),
        (b"{", "not valid JSON (line 1)"),
        (b'{"a": 1,}', "not valid JSON"),
        (b'{"a": 1, "a": 2}', "duplicate key"),
        (b'{"schema_version": 1, "schema_version": 1}', "duplicate key"),
        (b'{"schema_version": NaN}', "constant NaN"),
        (b'{"schema_version": Infinity}', "constant Infinity"),
        (b'{"schema_version": 1.0}', "fractional part"),
        (b'{"schema_version": 1e0}', "fractional part"),
        (b"[" * 200_000, "nested too deeply"),
        (b"x" * (MAX_BASELINE_BYTES + 1), f"larger than {MAX_BASELINE_BYTES} bytes"),
    ],
    ids=lambda v: repr(v)[:30],
)
def test_malformed_json_is_refused(data: bytes, message: str) -> None:
    with pytest.raises(BaselineError) as caught:
        parse_baseline(data)
    assert message in str(caught.value)


def test_a_byte_order_mark_is_accepted() -> None:
    data = b"\xef\xbb\xbf" + json.dumps(document()).encode("utf-8")
    assert parse_baseline(data).entries == (BaselineEntry("10.0.0.1", 22, "ssh"),)


def test_addresses_are_stored_in_canonical_form_and_entries_are_sorted() -> None:
    baseline = parse(
        document(
            entries=[
                entry(address="0:0:0:0:0:0:0:1", port=22),
                entry(address="10.0.0.9", port=1),
                entry(address="10.0.0.10", port=1),
            ]
        )
    )
    assert [e.address for e in baseline.entries] == ["10.0.0.9", "10.0.0.10", "::1"]


def test_the_maximum_number_of_entries_is_accepted_and_one_more_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store, "MAX_BASELINE_ENTRIES", 5)  # the real cap would make this slow

    def entries(count: int) -> list[dict[str, Any]]:
        return [entry(address="10.0.0.1", port=1 + n) for n in range(count)]

    assert len(parse(document(entries=entries(5))).entries) == 5
    with pytest.raises(BaselineError, match="more than 5 entries"):
        parse(document(entries=entries(6)))


def test_the_documented_entry_cap_is_the_most_one_scan_can_probe() -> None:
    assert MAX_BASELINE_ENTRIES == MAX_PROBES_PER_RUN


def test_hostile_text_in_a_rejected_baseline_is_not_echoed_raw() -> None:
    with pytest.raises(BaselineError) as caught:
        parse(document(**{"bad\x1b[31mkey": 1}))
    assert "\x1b" not in str(caught.value)


def test_a_baseline_file_is_read_from_disk_with_its_size_cap(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(document()), encoding="utf-8")
    assert load_baseline(path).entries == (BaselineEntry("10.0.0.1", 22, "ssh"),)
    path.write_bytes(b"x" * (MAX_BASELINE_BYTES + 5))
    with pytest.raises(BaselineError, match="larger than"):
        load_baseline(path)


def test_a_missing_file_and_a_directory_are_refused(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="cannot read"):
        load_baseline(tmp_path / "missing.json")
    with pytest.raises(BaselineError, match="not a regular file"):
        load_baseline(tmp_path)


# -- the comparison --------------------------------------------------------------------------


def baseline(*entries: tuple[str, int, str | None], created: str = CREATED) -> Baseline:
    return Baseline(SCHEMA_VERSION, created, tuple(BaselineEntry(*e) for e in entries))


def test_new_closed_changed_and_unscanned_entries_are_told_apart() -> None:
    before = baseline(
        ("10.0.0.1", 22, "ssh"),
        ("10.0.0.1", 80, "http"),
        ("10.0.0.1", 443, "tls"),
        ("10.0.0.1", 8000, None),
        ("10.0.0.9", 22, "ssh"),
    )
    now = baseline(
        ("10.0.0.1", 22, "ssh"),  # unchanged
        ("10.0.0.1", 80, "telnet"),  # changed
        ("10.0.0.1", 8000, "http"),  # changed from unidentified
        ("10.0.0.1", 9000, "ssh"),  # new
    )
    probed = [("10.0.0.1", p) for p in (22, 80, 443, 8000, 9000)]
    drift = diff_baselines(before, now, probed)
    assert drift.new == (BaselineEntry("10.0.0.1", 9000, "ssh"),)
    assert drift.closed == (BaselineEntry("10.0.0.1", 443, "tls"),)
    assert drift.changed == (
        (BaselineEntry("10.0.0.1", 80, "http"), BaselineEntry("10.0.0.1", 80, "telnet")),
        (BaselineEntry("10.0.0.1", 8000, None), BaselineEntry("10.0.0.1", 8000, "http")),
    )
    assert drift.not_scanned == (BaselineEntry("10.0.0.9", 22, "ssh"),)
    assert has_drift(drift)


def test_an_identical_scan_has_no_drift_whatever_its_time() -> None:
    before = baseline(("10.0.0.1", 22, "ssh"), created="2026-01-01T00:00:00+00:00")
    now = baseline(("10.0.0.1", 22, "ssh"), created="2030-06-01T00:00:00+00:00")
    drift = diff_baselines(before, now, [("10.0.0.1", 22)])
    assert (drift.new, drift.closed, drift.changed, drift.not_scanned) == ((), (), (), ())
    assert not has_drift(drift)


def test_entries_the_scan_did_not_cover_are_reported_but_are_not_drift() -> None:
    before = baseline(("10.0.0.1", 22, "ssh"))
    drift = diff_baselines(before, baseline(), [("10.0.0.2", 22)])
    assert drift.not_scanned == (BaselineEntry("10.0.0.1", 22, "ssh"),)
    assert not has_drift(drift)


def test_a_probed_port_that_is_no_longer_open_is_closed_whatever_the_reason() -> None:
    before = baseline(("10.0.0.1", 22, "ssh"))
    assert diff_baselines(before, baseline(), [("10.0.0.1", 22)]).closed == before.entries


def test_address_spellings_do_not_cause_false_drift() -> None:
    before = baseline(("::1", 22, "ssh"))
    now = baseline(("0:0:0:0:0:0:0:1", 22, "ssh"))
    drift = diff_baselines(before, now, [("0:0:0:0:0:0:0:1", 22)])
    assert not has_drift(drift)


def test_the_result_is_sorted_by_address_then_port() -> None:
    now = baseline(("10.0.0.10", 1, "a"), ("10.0.0.2", 9, "a"), ("10.0.0.2", 3, "a"))
    drift = diff_baselines(baseline(), now, [])
    assert [(e.address, e.port) for e in drift.new] == [
        ("10.0.0.2", 3),
        ("10.0.0.2", 9),
        ("10.0.0.10", 1),
    ]


def test_replace_keeps_the_tool_honest() -> None:
    assert replace(baseline(("10.0.0.1", 22, "ssh")), created_at="x").created_at == "x"
