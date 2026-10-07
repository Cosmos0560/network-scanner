from __future__ import annotations

import pytest

from network_scanner.core.limits import MAX_PORT_SPEC_CHARS
from network_scanner.ports.presets import load_preset
from network_scanner.ports.spec import PortErrorCode, PortSpecError, parse_ports

E = PortErrorCode
CAP = 1024


def error_of(text: str, max_ports: int = CAP) -> PortSpecError:
    with pytest.raises(PortSpecError) as caught:
        parse_ports(text, max_ports=max_ports)
    return caught.value


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("22", (22,)),
        ("1", (1,)),
        ("65535", (65535,)),
        ("80,22,443", (22, 80, 443)),
        ("22,22,22", (22,)),
        ("1-5", (1, 2, 3, 4, 5)),
        ("5-5", (5,)),
        ("20-23,22", (20, 21, 22, 23)),
        ("1-3,4-6", (1, 2, 3, 4, 5, 6)),
        ("10-20,15-25,30", (*range(10, 26), 30)),
        ("65530-65535", (65530, 65531, 65532, 65533, 65534, 65535)),
    ],
)
def test_lists_and_ranges_are_sorted_and_deduplicated(text: str, expected: tuple[int, ...]) -> None:
    assert parse_ports(text, max_ports=CAP) == expected


def test_the_common_preset_can_be_used_alone_or_mixed() -> None:
    common = load_preset("common").ports
    assert parse_ports("common", max_ports=CAP) == common
    mixed = parse_ports("common,8000-8002,22,9", max_ports=CAP)
    assert mixed == tuple(sorted({*common, 8000, 8001, 8002, 9}))
    assert parse_ports("common,common", max_ports=CAP) == common


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("", E.EMPTY_SPEC),
        (",", E.EMPTY_ITEM),
        (",22", E.EMPTY_ITEM),
        ("22,", E.EMPTY_ITEM),
        ("22,,80", E.EMPTY_ITEM),
        ("0", E.INVALID_PORT),
        ("65536", E.INVALID_PORT),
        ("99999", E.INVALID_PORT),
        ("100000", E.INVALID_PORT),
        ("080", E.INVALID_PORT),
        ("00", E.INVALID_PORT),
        ("+80", E.INVALID_PORT),
        ("0x50", E.INVALID_PORT),
        ("1e3", E.INVALID_PORT),
        ("22.5", E.INVALID_PORT),
        ("Common", E.INVALID_PORT),
        ("-80", E.INVALID_RANGE),
        ("80-", E.INVALID_RANGE),
        ("-", E.INVALID_RANGE),
        ("80-70", E.INVALID_RANGE),
        ("0-5", E.INVALID_RANGE),
        ("1-65536", E.INVALID_RANGE),
        ("1-2-3", E.INVALID_RANGE),
        ("080-90", E.INVALID_RANGE),
        ("nope", E.UNKNOWN_PRESET),
        ("common-1", E.UNKNOWN_PRESET),
        ("top100", E.UNKNOWN_PRESET),
        ("22 ", E.INVALID_CHARACTERS),
        (" 22", E.INVALID_CHARACTERS),
        ("22, 80", E.INVALID_CHARACTERS),
        ("2\t2", E.INVALID_CHARACTERS),
        ("22\n", E.INVALID_CHARACTERS),
        ("22\x00", E.INVALID_CHARACTERS),
        ("\x1b[31m22", E.INVALID_CHARACTERS),
        ("22" + chr(0x200B), E.INVALID_CHARACTERS),
        ("22" + chr(0xA0), E.INVALID_CHARACTERS),
        (chr(0x662) * 2, E.INVALID_CHARACTERS),  # Arabic-Indic digits
        (chr(0xFF12) + "2", E.INVALID_CHARACTERS),  # fullwidth digit
        ("1," * (MAX_PORT_SPEC_CHARS // 2 + 1), E.SPEC_TOO_LONG),
        ("9" * 100_000, E.SPEC_TOO_LONG),
    ],
    ids=lambda v: repr(v)[:40],
)
def test_malformed_specs_are_refused_with_a_stable_code(text: str, code: PortErrorCode) -> None:
    assert error_of(text).code is code


def test_the_distinct_port_cap_is_exact() -> None:
    assert len(parse_ports("1-1024", max_ports=1024)) == 1024
    assert error_of("1-1025").code is E.TOO_MANY_PORTS
    assert error_of("1-1024,2000").code is E.TOO_MANY_PORTS
    assert len(parse_ports("1-65535", max_ports=65535)) == 65535
    assert error_of("1-65535", max_ports=65534).code is E.TOO_MANY_PORTS


def test_overlap_does_not_inflate_the_count() -> None:
    assert parse_ports("1-1000,1-1000,500-1000,1-10", max_ports=1000) == tuple(range(1, 1001))


def test_a_spec_that_repeats_the_whole_port_space_is_judged_arithmetically() -> None:
    spec = ",".join(["1-65535"] * 500)
    assert len(spec) < MAX_PORT_SPEC_CHARS
    assert error_of(spec, max_ports=1024).code is E.TOO_MANY_PORTS
    assert len(parse_ports(spec, max_ports=65535)) == 65535


def test_the_common_preset_obeys_the_cap_too() -> None:
    size = len(load_preset("common").ports)
    assert error_of("common", max_ports=size - 1).code is E.TOO_MANY_PORTS
    assert len(parse_ports("common", max_ports=size)) == size


def test_the_error_message_carries_the_code() -> None:
    error = error_of("0")
    assert str(error).startswith("invalid_port: ")
    assert error.detail in str(error)
