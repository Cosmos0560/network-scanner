from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from network_scanner.core.errors import NetErrorCode, ReasonCode
from network_scanner.core.limits import DEFAULT_LIMITS
from network_scanner.core.model import (
    SCHEMA_VERSION,
    AddressClass,
    Baseline,
    BaselineEntry,
    Confidence,
    Drift,
    Family,
    Finding,
    PortResult,
    PortState,
    ResolvedTarget,
    ScanReport,
    ScopeDecision,
    Severity,
    TargetKind,
    TargetSpec,
    TlsInfo,
    to_jsonable,
)


def make_report() -> ScanReport:
    spec = TargetSpec(raw="127.0.0.1", kind=TargetKind.IP)
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version="0.1.0",
        started_at="2026-01-01T00:00:00+00:00",
        complete=True,
        probed=False,
        limits=DEFAULT_LIMITS,
        targets=(ResolvedTarget("127.0.0.1", "127.0.0.1", Family.IPV4, spec),),
        results=(
            PortResult("127.0.0.1", 22, PortState.OPEN, None),
            PortResult("127.0.0.1", 23, PortState.CLOSED, NetErrorCode.REFUSED),
        ),
        observations=(),
        findings=(
            Finding(
                id="X-1",
                title="t",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                address="127.0.0.1",
                port=22,
                evidence="banner said so",
                references=("RFC 4253",),
            ),
        ),
    )


def test_report_serialises_to_plain_json_types() -> None:
    data = to_jsonable(make_report())
    text = json.dumps(data, sort_keys=True)
    assert json.loads(text) == data
    assert data["schema_version"] == 1
    assert data["limits"]["connect_timeout_s"] == 3.0
    assert data["targets"][0]["family"] == "ipv4"
    assert data["targets"][0]["origin_spec"] == {"raw": "127.0.0.1", "kind": "ip"}
    assert data["results"][1] == {
        "address": "127.0.0.1",
        "port": 23,
        "state": "closed",
        "error_code": "refused",
    }
    assert data["findings"][0]["severity"] == "high"
    assert data["findings"][0]["references"] == ["RFC 4253"]


def test_enums_become_plain_strings() -> None:
    value = to_jsonable(Severity.HIGH)
    assert value == "high"
    assert type(value) is str


def test_scalars_pass_through() -> None:
    assert to_jsonable(None) is None
    assert to_jsonable(True) is True
    assert to_jsonable(3) == 3
    assert to_jsonable(1.5) == 1.5
    assert to_jsonable("s") == "s"
    assert to_jsonable([1, (2, 3)]) == [1, [2, 3]]


@pytest.mark.parametrize("unsupported", [{1}, {"a": 1}, object(), b"bytes"])
def test_unsupported_values_are_rejected(unsupported: Any) -> None:
    with pytest.raises(TypeError, match="cannot serialise"):
        to_jsonable(unsupported)


def test_dataclass_types_themselves_are_rejected() -> None:
    with pytest.raises(TypeError):
        to_jsonable(TargetSpec)


def test_model_values_are_immutable() -> None:
    result = PortResult("127.0.0.1", 22, PortState.OPEN, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.port = 80  # type: ignore[misc]


def test_severity_ranks_are_ordered() -> None:
    ordered = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert [s.rank for s in ordered] == [0, 1, 2, 3, 4]


def test_self_issued_and_self_signature_are_separate_facts() -> None:
    names = {f.name for f in dataclasses.fields(TlsInfo)}
    assert {"self_issued", "self_signature_valid"} <= names


def test_the_reason_codes_named_in_the_plan_exist() -> None:
    assert {
        "ambiguous_numeric",
        "embedded_ipv4",
        "public_not_allowed",
        "not_in_scope_file",
        "mixed_dns_answers",
        "too_many_targets",
    } <= {code.value for code in ReasonCode}


def test_scope_decision_serialises() -> None:
    assert {code.value for code in ReasonCode} >= {
        "ambiguous_numeric",
        "embedded_ipv4",
        "public_not_allowed",
        "not_in_scope_file",
        "mixed_dns_answers",
        "too_many_targets",
    }
    decision = ScopeDecision(False, AddressClass.PUBLIC, ReasonCode.PUBLIC_NOT_ALLOWED)
    assert to_jsonable(decision) == {
        "allowed": False,
        "address_class": "public",
        "reason_code": "public_not_allowed",
    }


def test_baseline_and_drift_serialise() -> None:
    old = BaselineEntry("10.0.0.1", 22, "ssh")
    new = BaselineEntry("10.0.0.1", 22, "telnet")
    baseline = Baseline(SCHEMA_VERSION, "2026-01-01T00:00:00+00:00", (old,))
    drift = Drift(new=(), closed=(), changed=((old, new),), not_scanned=())
    assert to_jsonable(baseline)["entries"] == [
        {"address": "10.0.0.1", "port": 22, "service": "ssh"}
    ]
    assert to_jsonable(drift)["changed"][0][1]["service"] == "telnet"
