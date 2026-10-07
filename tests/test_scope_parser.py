from __future__ import annotations

import ipaddress
import itertools
import socket

import pytest

from network_scanner.core.errors import ReasonCode, ScopeRefusal
from network_scanner.core.model import Family, TargetKind
from network_scanner.scope.parser import (
    Address,
    CidrTarget,
    HostnameTarget,
    IpTarget,
    ParsedTarget,
    RangeTarget,
    count_addresses,
    expand,
    format_v6,
    parse_ip,
    parse_target,
)

R = ReasonCode


def shown(value: object) -> str:
    return repr(value)[:50]


def refusal(raw: str) -> ReasonCode:
    with pytest.raises(ScopeRefusal) as caught:
        parse_target(raw)
    return caught.value.reason_code


# -- accepted forms -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("0.0.0.0", "0.0.0.0"),
        ("127.0.0.1", "127.0.0.1"),
        ("255.255.255.255", "255.255.255.255"),
        ("192.168.1.10", "192.168.1.10"),
        ("::", "::"),
        ("::1", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("FE80::ABCD", "fe80::abcd"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
        ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
        ("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"),
        ("::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8"),
        ("::ffff:1.2.3.4", "::ffff:102:304"),
        ("64:ff9b::1.2.3.4", "64:ff9b::102:304"),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("fe80::1%Wi-Fi_0.1", "fe80::1%Wi-Fi_0.1"),
        ("fe80::1%25eth0", "fe80::1%25eth0"),  # never percent-decoded: the zone is "25eth0"
        ("febf::1%a", "febf::1%a"),
    ],
)
def test_ip_literals_are_accepted_and_canonicalised(raw: str, canonical: str) -> None:
    target = parse_target(raw)
    assert isinstance(target, IpTarget)
    assert target.address.text == canonical
    assert target.spec.kind is TargetKind.IP
    assert target.spec.raw == raw


def test_families_and_bits() -> None:
    v4, v6 = parse_ip("10.0.0.1"), parse_ip("::1")
    assert (v4.family, v4.bits) == (Family.IPV4, 32)
    assert (v6.family, v6.bits) == (Family.IPV6, 128)
    assert v4.sort_key() < v6.sort_key()


def test_hostnames_are_accepted_and_lower_cased() -> None:
    for raw, name in [
        ("router", "router"),
        ("My-Host.LAB", "my-host.lab"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a" * 63 + ".example", "a" * 63 + ".example"),
        ("1-2.example.com", "1-2.example.com"),
        ("0xdead.example.com", "0xdead.example.com"),
        ("a-b-c", "a-b-c"),
        ("localhost", "localhost"),
    ]:
        target = parse_target(raw)
        assert isinstance(target, HostnameTarget), raw
        assert target.name == name
        assert target.spec.kind is TargetKind.HOSTNAME


def test_a_hostname_of_253_characters_is_accepted_and_254_is_not() -> None:
    labels = ["a" * 63, "b" * 63, "c" * 63, "d" * 61]
    name = ".".join(labels)
    assert len(name) == 253
    assert isinstance(parse_target(name), HostnameTarget)
    assert refusal(name + "e") is R.INVALID_HOSTNAME


# -- ranges ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "start", "end"),
    [
        ("10.0.0.1-5", "10.0.0.1", "10.0.0.5"),
        ("10.0.0.1-10.0.0.1", "10.0.0.1", "10.0.0.1"),
        ("10.0.0.250-10.0.1.5", "10.0.0.250", "10.0.1.5"),
        ("10.0.0.0-255", "10.0.0.0", "10.0.0.255"),
        ("192.168.0.9-192.168.3.200", "192.168.0.9", "192.168.3.200"),
    ],
)
def test_ranges_are_accepted(raw: str, start: str, end: str) -> None:
    target = parse_target(raw)
    assert isinstance(target, RangeTarget)
    assert (target.start.text, target.end.text) == (start, end)
    assert target.spec.kind is TargetKind.RANGE


# -- CIDR -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "network", "prefix"),
    [
        ("10.0.0.0/8", "10.0.0.0", 8),
        ("192.168.1.0/24", "192.168.1.0", 24),
        ("192.168.1.4/30", "192.168.1.4", 30),
        ("192.168.1.4/31", "192.168.1.4", 31),
        ("192.168.1.4/32", "192.168.1.4", 32),
        ("0.0.0.0/0", "0.0.0.0", 0),
        ("fd00::/8", "fd00::", 8),
        ("fd00::100/120", "fd00::100", 120),
        ("::1/128", "::1", 128),
        ("::/0", "::", 0),
    ],
)
def test_cidr_blocks_are_accepted(raw: str, network: str, prefix: int) -> None:
    target = parse_target(raw)
    assert isinstance(target, CidrTarget)
    assert (target.network.text, target.prefix) == (network, prefix)
    assert target.spec.kind is TargetKind.CIDR


# -- refusals, each with its reason code ------------------------------------------------------

REFUSED = [
    # ambiguous numeric forms (decimal, hex, octal, short, leading zeros)
    ("2130706433", R.AMBIGUOUS_NUMERIC),
    ("0x7f000001", R.AMBIGUOUS_NUMERIC),
    ("0x7f.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("0x7f.0x0.0x0.0x1", R.AMBIGUOUS_NUMERIC),
    ("0177.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("0177.0.0.01", R.AMBIGUOUS_NUMERIC),
    ("127.1", R.AMBIGUOUS_NUMERIC),
    ("127.0.1", R.AMBIGUOUS_NUMERIC),
    ("010.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("1.2.3", R.AMBIGUOUS_NUMERIC),
    ("1.2.3.4.5", R.AMBIGUOUS_NUMERIC),
    ("00.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("0", R.AMBIGUOUS_NUMERIC),
    ("0x", R.AMBIGUOUS_NUMERIC),
    ("host.123", R.AMBIGUOUS_NUMERIC),
    ("::1.2.3", R.AMBIGUOUS_NUMERIC),
    ("::ffff:010.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("10.0.0.0/8".replace("10.0.0.0", "10.0.0"), R.AMBIGUOUS_NUMERIC),
    ("127.1/8", R.AMBIGUOUS_NUMERIC),
    ("10.0.1-5", R.AMBIGUOUS_NUMERIC),
    ("010.0.0.1-5", R.AMBIGUOUS_NUMERIC),
    ("10.0.0.1-05", R.AMBIGUOUS_NUMERIC),
    ("10.0.0.1-10.0.0", R.AMBIGUOUS_NUMERIC),
    ("\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11", R.AMBIGUOUS_NUMERIC),
    ("127\u30020\u30020\u30021", R.AMBIGUOUS_NUMERIC),
    ("10.0.0.\u00b2", R.AMBIGUOUS_NUMERIC),  # superscript two folds to 2 under NFKC
    ("10.0.0.\u2460", R.AMBIGUOUS_NUMERIC),  # circled one folds to 1 under NFKC
    ("\u00b9\u00b2\u2077.0.0.1", R.AMBIGUOUS_NUMERIC),
    ("127\uff610\uff610\uff611", R.AMBIGUOUS_NUMERIC),
    ("\u0661\u0662\u0667.0.0.1", R.AMBIGUOUS_NUMERIC),
    # not an address at all
    ("256.1.1.1", R.INVALID_TARGET),
    ("999.0.0.1-5", R.INVALID_TARGET),
    ("127.0.0.1:80", R.INVALID_TARGET),
    ("[::1]", R.INVALID_TARGET),
    ("http://127.0.0.1", R.INVALID_TARGET),
    ("::g", R.INVALID_TARGET),
    ("1::2::3", R.INVALID_TARGET),
    (":::", R.INVALID_TARGET),
    ("1:::2", R.INVALID_TARGET),
    (":1:2:3:4:5:6:7", R.INVALID_TARGET),
    ("1:2:3:4:5:6:7:", R.INVALID_TARGET),
    ("1:2:3:4:5:6:7", R.INVALID_TARGET),
    ("1:2:3:4:5:6:7:8:9", R.INVALID_TARGET),
    ("1:2:3:4:5:6:7::8", R.INVALID_TARGET),
    ("12345::", R.INVALID_TARGET),
    ("::1.2.3.256", R.INVALID_TARGET),
    ("1.2.3.4::", R.INVALID_TARGET),
    ("1.2.3.4:1::", R.INVALID_TARGET),
    ("::1:", R.INVALID_TARGET),
    ("", R.INVALID_TARGET),
    # zone ids
    ("fd00::1%eth0", R.INVALID_ZONE_ID),
    ("::1%eth0", R.INVALID_ZONE_ID),
    ("2001:db8::1%eth0", R.INVALID_ZONE_ID),
    ("fe80::1%", R.INVALID_ZONE_ID),
    ("fe80::1%a" + "b" * 16, R.INVALID_ZONE_ID),
    ("fe80::1%eth0%eth1", R.INVALID_ZONE_ID),
    ("fe80::1%e/th", R.INVALID_ZONE_ID),
    ("fe80::1%eth!", R.INVALID_ZONE_ID),
    ("fec0::1%eth0", R.INVALID_ZONE_ID),
    # CIDR
    ("192.168.1.5/24", R.CIDR_HOST_BITS),
    ("127.0.0.1/8", R.CIDR_HOST_BITS),
    ("::1/64", R.CIDR_HOST_BITS),
    ("10.0.0.0/33", R.INVALID_CIDR),
    ("10.0.0.0/-1", R.INVALID_CIDR),
    ("10.0.0.0/+8", R.INVALID_CIDR),
    ("10.0.0.0/08", R.INVALID_CIDR),
    ("10.0.0.0/", R.INVALID_CIDR),
    ("/8", R.INVALID_CIDR),
    ("10.0.0.0/8/8", R.INVALID_CIDR),
    ("10.0.0.0/\u0668", R.AMBIGUOUS_NUMERIC),
    ("10.0.0.0/1000", R.INVALID_CIDR),
    ("::/129", R.INVALID_CIDR),
    ("fe80::%eth0/64", R.INVALID_ZONE_ID),
    ("fe80::/64%eth0", R.INVALID_CIDR),
    ("example.com/24", R.INVALID_CIDR),
    # ranges
    ("10.0.0.9-10.0.0.1", R.INVALID_RANGE),
    ("10.0.0.5-4", R.INVALID_RANGE),
    ("10.0.0.1-256", R.INVALID_RANGE),
    ("10.0.0.1-", R.INVALID_RANGE),
    ("10.0.0.1-a", R.INVALID_RANGE),
    ("10.0.0.1-5-6", R.INVALID_RANGE),
    ("10.0.0.1-10.0.x.5", R.INVALID_RANGE),
    ("10.0.0.1-::1", R.INVALID_RANGE),
    ("::1-::5", R.INVALID_RANGE),
    ("fe80::1-fe80::5", R.INVALID_RANGE),
    # hostnames
    ("example.com.", R.INVALID_HOSTNAME),
    ("1.2.3.4.", R.INVALID_HOSTNAME),
    (".example.com", R.INVALID_HOSTNAME),
    ("a..b", R.INVALID_HOSTNAME),
    ("exa_mple.com", R.INVALID_HOSTNAME),
    ("-leading.example", R.INVALID_HOSTNAME),
    ("trailing-.example", R.INVALID_HOSTNAME),
    ("user@host", R.INVALID_HOSTNAME),
    ("host!", R.INVALID_HOSTNAME),
    ("a" * 64 + ".example", R.INVALID_HOSTNAME),
    ("b\u00fccher.example", R.INVALID_HOSTNAME),
    ("\u0433\u0443\u0433\u043b.example", R.INVALID_HOSTNAME),
    ("-", R.INVALID_HOSTNAME),
    ("b\u00fccher1.example", R.INVALID_HOSTNAME),  # a non-ASCII name with an ASCII digit
    # characters and length
    ("a\x00b", R.INVALID_CHARACTERS),
    ("127.0.0.1\x00", R.INVALID_CHARACTERS),
    ("\x00", R.INVALID_CHARACTERS),
    (" 127.0.0.1", R.INVALID_CHARACTERS),
    ("127.0.0.1 ", R.INVALID_CHARACTERS),
    ("127.0.0.1\n", R.INVALID_CHARACTERS),
    ("127.0.0.1\r\n", R.INVALID_CHARACTERS),
    ("127.0.0.1\t", R.INVALID_CHARACTERS),
    ("127.0.0.\u00a01", R.INVALID_CHARACTERS),
    ("host\u202eexe.example", R.INVALID_CHARACTERS),
    ("host\u200b.example", R.INVALID_CHARACTERS),
    ("\x1b[31m127.0.0.1", R.INVALID_CHARACTERS),
    ("10.0.0.1 -5", R.INVALID_CHARACTERS),
    ("a" * 256, R.TARGET_TOO_LONG),
    ("1" * 100_000, R.TARGET_TOO_LONG),
]


@pytest.mark.parametrize(("raw", "reason"), REFUSED, ids=[shown(r) for r, _ in REFUSED])
def test_every_ambiguous_or_malformed_form_is_refused_with_its_code(
    raw: str, reason: ReasonCode
) -> None:
    assert refusal(raw) is reason


def test_a_target_of_exactly_255_characters_is_judged_on_its_content() -> None:
    raw = ".".join(["a" * 63] * 4)
    assert len(raw) == 255
    assert refusal(raw) is R.INVALID_HOSTNAME  # not TARGET_TOO_LONG


def test_parse_ip_accepts_only_a_single_address() -> None:
    assert parse_ip("10.0.0.1") == Address(Family.IPV4, 0x0A000001)
    for raw in ("10.0.0.0/8", "10.0.0.1-5", "example.com"):
        with pytest.raises(ScopeRefusal) as caught:
            parse_ip(raw)
        assert caught.value.reason_code is R.INVALID_TARGET
    with pytest.raises(ScopeRefusal) as ambiguous:
        parse_ip("127.1")
    assert ambiguous.value.reason_code is R.AMBIGUOUS_NUMERIC


def test_a_refusal_never_carries_raw_control_characters() -> None:
    hostile = "\x1b[31mevil\x00\u202e\r\nnext"
    with pytest.raises(ScopeRefusal) as caught:
        parse_target(hostile)
    for text in (caught.value.target, str(caught.value)):
        assert not any(c in text for c in "\x1b\x00\u202e\r\n")


def test_a_very_long_hostile_input_is_refused_quickly_and_shows_a_short_target() -> None:
    with pytest.raises(ScopeRefusal) as caught:
        parse_target("\x1b" * 5_000_000)
    assert caught.value.reason_code is R.TARGET_TOO_LONG
    assert len(caught.value.target) <= 80


# -- counting and expansion -------------------------------------------------------------------


def targets(raw: str) -> ParsedTarget:
    return parse_target(raw)


@pytest.mark.parametrize(
    ("raw", "count"),
    [
        ("10.0.0.1", 1),
        ("example.com", 1),
        ("10.0.0.0/24", 254),
        ("10.0.0.0/30", 2),
        ("10.0.0.0/31", 2),
        ("10.0.0.1/32", 1),
        ("10.0.0.0/8", 2**24 - 2),
        ("0.0.0.0/0", 2**32 - 2),
        ("10.0.0.1-10.0.0.1", 1),
        ("10.0.0.1-200", 200),
        ("10.0.0.250-10.0.1.5", 12),
        ("fd00::/120", 256),
        ("fd00::/127", 2),
        ("fd00::1/128", 1),
        ("fd00::/8", 2**120),
        ("::/0", 2**128),
    ],
)
def test_counts_are_computed_arithmetically(raw: str, count: int) -> None:
    assert count_addresses(targets(raw)) == count


def test_expansion_matches_the_count_and_skips_network_and_broadcast() -> None:
    target = targets("192.168.1.0/29")
    assert isinstance(target, CidrTarget)
    texts = [a.text for a in expand(target)]
    assert texts == [f"192.168.1.{n}" for n in range(1, 7)]
    assert len(texts) == count_addresses(target)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.0/31", ["192.168.1.0", "192.168.1.1"]),
        ("192.168.1.7/32", ["192.168.1.7"]),
        ("10.0.0.254-10.0.1.1", ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]),
        ("fd00::/126", ["fd00::", "fd00::1", "fd00::2", "fd00::3"]),
        ("10.0.0.5", ["10.0.0.5"]),
    ],
)
def test_expansion_covers_exactly_the_expected_addresses(raw: str, expected: list[str]) -> None:
    target = targets(raw)
    assert isinstance(target, (IpTarget, CidrTarget, RangeTarget))
    assert [a.text for a in expand(target)] == expected


def test_counting_a_huge_block_does_not_iterate_it() -> None:
    assert count_addresses(targets("::/0")) == 2**128  # would never finish if it looped


# -- exhaustive checks over small alphabets (no randomness) -------------------------------------


def parse_or_none(text: str) -> ParsedTarget | None:
    """Parse, treating a ScopeRefusal as 'refused'. Any other exception is a test failure."""
    try:
        return parse_target(text)
    except ScopeRefusal:
        return None


def all_strings(alphabet: str, max_len: int) -> list[str]:
    return [
        "".join(chars)
        for length in range(1, max_len + 1)
        for chars in itertools.product(alphabet, repeat=length)
    ]


def test_nothing_that_inet_aton_reads_as_an_address_is_ever_accepted_as_anything_else() -> None:
    """inet_aton (and so getaddrinfo) takes decimal, octal, hex and short forms. If it reads a
    string as an address, we must refuse the string or read it as exactly the same address."""
    checked = 0
    for text in all_strings("01279x.f", 6):
        try:
            packed = socket.inet_aton(text)
        except OSError:
            continue
        checked += 1
        try:
            target = parse_target(text)
        except ScopeRefusal:
            continue
        assert isinstance(target, IpTarget), text
        assert target.address.value == int.from_bytes(packed, "big"), text
        assert target.address.text == text, text
    assert checked > 10_000  # the check really saw many inputs


def test_accepted_targets_round_trip_and_everything_else_is_a_refusal() -> None:
    accepted = refused = 0
    for text in all_strings(":01f.%/-x", 5):
        target = parse_or_none(text)
        if target is None:
            refused += 1
            continue
        accepted += 1
        if isinstance(target, IpTarget):
            assert parse_target(target.address.text) == IpTarget(
                target.address.text, target.address
            )
        elif isinstance(target, CidrTarget):
            again = parse_target(f"{target.network.text}/{target.prefix}")
            assert isinstance(again, CidrTarget)
            assert (again.network, again.prefix) == (target.network, target.prefix)
        elif isinstance(target, RangeTarget):
            assert target.start.value <= target.end.value
        else:
            assert target.name == text.lower()
    assert accepted > 100
    assert refused > 10_000


def test_ipv6_acceptance_agrees_with_the_standard_library_in_both_directions() -> None:
    both = 0
    for text in all_strings(":0f1", 8):
        ours = None
        try:
            parsed = parse_target(text)
            ours = parsed.address.value if isinstance(parsed, IpTarget) else None
        except ScopeRefusal:
            pass
        try:
            theirs: int | None = int(ipaddress.IPv6Address(text))
        except ValueError:
            theirs = None
        assert ours == theirs, text
        both += ours is not None
    assert both > 1000


def test_ipv6_formatting_agrees_with_the_standard_library() -> None:
    groups = (0, 1, 0xFFFF, 0x1234)
    checked = 0
    for combo in itertools.product(groups, repeat=8):
        value = 0
        for group in combo:
            value = (value << 16) | group
        if value >> 32 == 0xFFFF:  # IPv4-mapped: ipaddress changed how it prints these
            continue
        assert format_v6(value) == str(ipaddress.IPv6Address(value))
        checked += 1
    assert checked > 60_000
