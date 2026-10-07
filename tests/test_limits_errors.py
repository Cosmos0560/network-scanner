from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from network_scanner.core.errors import (
    ConnectError,
    ExitCode,
    LimitError,
    NetErrorCode,
    NetworkScannerError,
    UsageError,
)
from network_scanner.core.limits import CEILINGS, DEFAULT_LIMITS, Limits

# PLAN.md section 4.6, written out independently of the implementation.
PLAN_DEFAULTS = {
    "max_targets": 256,
    "max_ports_per_target": 1024,
    "concurrency": 64,
    "connections_per_second": 100,
    "connect_timeout_s": 3.0,
    "banner_timeout_s": 2.0,
    "banner_max_bytes": 1024,
    "total_timeout_s": 300.0,
    "probes_per_open_port": 3,
}
PLAN_CEILINGS = {
    "max_targets": 4096,
    "max_ports_per_target": 65535,
    "concurrency": 512,
    "connections_per_second": 1000,
    "connect_timeout_s": 30.0,
    "banner_timeout_s": 10.0,
    "banner_max_bytes": 4096,
    "total_timeout_s": 3600.0,
    "probes_per_open_port": 3,
}
FIELD_NAMES = [f.name for f in dataclasses.fields(Limits)]


def build_limits(**fields: Any) -> Limits:
    return Limits(**fields)


def test_defaults_match_the_plan() -> None:
    assert dataclasses.asdict(DEFAULT_LIMITS) == PLAN_DEFAULTS
    assert Limits() == DEFAULT_LIMITS


def test_ceilings_match_the_plan_and_cover_every_field() -> None:
    assert CEILINGS == PLAN_CEILINGS
    assert set(CEILINGS) == set(FIELD_NAMES)


@pytest.mark.parametrize("name", FIELD_NAMES)
def test_a_value_at_the_ceiling_is_accepted(name: str) -> None:
    value = build_limits(**{name: PLAN_CEILINGS[name]})
    assert getattr(value, name) == PLAN_CEILINGS[name]


@pytest.mark.parametrize("name", FIELD_NAMES)
def test_a_value_past_the_ceiling_is_rejected(name: str) -> None:
    ceiling = PLAN_CEILINGS[name]
    with pytest.raises(LimitError, match=name):
        build_limits(**{name: ceiling + 1})


@pytest.mark.parametrize("name", FIELD_NAMES)
@pytest.mark.parametrize("bad", [0, -1])
def test_zero_and_negative_values_are_rejected(name: str, bad: int) -> None:
    with pytest.raises(LimitError, match=name):
        build_limits(**{name: bad})


@pytest.mark.parametrize("bad", [True, "5", None, float("nan")])
def test_non_numbers_booleans_and_nan_are_rejected(bad: Any) -> None:
    with pytest.raises(LimitError):
        Limits(concurrency=bad)


def test_limits_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_LIMITS.concurrency = 1  # type: ignore[misc]


def test_exit_codes_match_the_plan() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "FINDINGS": 1,
        "USAGE": 2,
        "RUNTIME": 3,
        "INTERRUPTED": 130,
    }


def test_error_hierarchy() -> None:
    assert issubclass(LimitError, UsageError)
    assert issubclass(UsageError, NetworkScannerError)
    assert issubclass(ConnectError, NetworkScannerError)


def test_connect_error_carries_its_code() -> None:
    error = ConnectError(NetErrorCode.REFUSED)
    assert error.code is NetErrorCode.REFUSED
    assert str(error) == "refused"
