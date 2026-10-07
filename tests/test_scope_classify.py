from __future__ import annotations

import pytest

from network_scanner.core.model import AddressClass as C
from network_scanner.core.model import Family
from network_scanner.scope import classify as classify_module
from network_scanner.scope.classify import (
    ALWAYS_REFUSED,
    DEFAULT_ALLOWED,
    V4_TABLE,
    V6_TABLE,
    classes_in_range,
    classify,
    policy_text,
    table_markdown,
)
from network_scanner.scope.parser import Address, parse_ip

CASES: list[tuple[str, C]] = [
    # IPv4: both edges of every block, and the address just outside it
    ("0.0.0.0", C.UNSPECIFIED),
    ("0.255.255.255", C.UNSPECIFIED),
    ("1.0.0.0", C.PUBLIC),
    ("9.255.255.255", C.PUBLIC),
    ("10.0.0.0", C.PRIVATE),
    ("10.255.255.255", C.PRIVATE),
    ("11.0.0.0", C.PUBLIC),
    ("100.63.255.255", C.PUBLIC),
    ("100.64.0.0", C.PUBLIC),  # CGNAT is public (decision D4)
    ("100.127.255.255", C.PUBLIC),
    ("100.128.0.0", C.PUBLIC),
    ("126.255.255.255", C.PUBLIC),
    ("127.0.0.0", C.LOOPBACK),
    ("127.0.0.1", C.LOOPBACK),
    ("127.255.255.255", C.LOOPBACK),
    ("128.0.0.0", C.PUBLIC),
    ("169.253.255.255", C.PUBLIC),
    ("169.254.0.0", C.LINK_LOCAL_V4),
    ("169.254.169.254", C.LINK_LOCAL_V4),  # cloud metadata (decision D4)
    ("169.254.255.255", C.LINK_LOCAL_V4),
    ("169.255.0.0", C.PUBLIC),
    ("172.15.255.255", C.PUBLIC),
    ("172.16.0.0", C.PRIVATE),
    ("172.31.255.255", C.PRIVATE),
    ("172.32.0.0", C.PUBLIC),
    ("191.255.255.255", C.PUBLIC),
    ("192.0.0.0", C.RESERVED),
    ("192.0.0.255", C.RESERVED),
    ("192.0.1.0", C.PUBLIC),
    ("192.0.2.0", C.DOCUMENTATION),
    ("192.0.2.255", C.DOCUMENTATION),
    ("192.0.3.0", C.PUBLIC),
    ("192.88.98.255", C.PUBLIC),
    ("192.88.99.0", C.RESERVED),
    ("192.88.99.255", C.RESERVED),
    ("192.88.100.0", C.PUBLIC),
    ("192.167.255.255", C.PUBLIC),
    ("192.168.0.0", C.PRIVATE),
    ("192.168.255.255", C.PRIVATE),
    ("192.169.0.0", C.PUBLIC),
    ("198.17.255.255", C.PUBLIC),
    ("198.18.0.0", C.BENCHMARK),
    ("198.19.255.255", C.BENCHMARK),
    ("198.20.0.0", C.PUBLIC),
    ("198.51.99.255", C.PUBLIC),
    ("198.51.100.0", C.DOCUMENTATION),
    ("198.51.100.255", C.DOCUMENTATION),
    ("198.51.101.0", C.PUBLIC),
    ("203.0.112.255", C.PUBLIC),
    ("203.0.113.0", C.DOCUMENTATION),
    ("203.0.113.255", C.DOCUMENTATION),
    ("203.0.114.0", C.PUBLIC),
    ("223.255.255.255", C.PUBLIC),
    ("224.0.0.0", C.MULTICAST),
    ("224.0.0.1", C.MULTICAST),
    ("239.255.255.255", C.MULTICAST),
    ("240.0.0.0", C.RESERVED),
    ("255.255.255.254", C.RESERVED),
    ("255.255.255.255", C.BROADCAST),
    ("8.8.8.8", C.PUBLIC),
    # IPv6
    ("::", C.UNSPECIFIED),
    ("::1", C.LOOPBACK),
    ("::2", C.EMBEDDED_IPV4),  # IPv4-compatible
    ("::10.0.0.1", C.EMBEDDED_IPV4),
    ("::ffff:ffff", C.EMBEDDED_IPV4),
    ("::1:0:0", C.RESERVED),
    ("::ffff:10.0.0.1", C.EMBEDDED_IPV4),  # IPv4-mapped
    ("::ffff:127.0.0.1", C.EMBEDDED_IPV4),
    ("::ffff:0:10.0.0.1", C.EMBEDDED_IPV4),  # IPv4-translated
    ("64:ff9b::10.0.0.1", C.EMBEDDED_IPV4),  # NAT64
    ("64:ff9b::ffff:ffff", C.EMBEDDED_IPV4),
    ("64:ff9b:1::1", C.EMBEDDED_IPV4),  # local-use NAT64
    ("64:ff9c::1", C.RESERVED),
    ("2001::1", C.EMBEDDED_IPV4),  # Teredo
    ("2001:0:ffff::1", C.EMBEDDED_IPV4),
    ("2001:1::1", C.RESERVED),
    ("2001:2::1", C.BENCHMARK),
    ("2001:3::1", C.RESERVED),
    ("2001:1ff:ffff::1", C.RESERVED),
    ("2001:200::1", C.PUBLIC),
    ("2001:db8::1", C.DOCUMENTATION),
    ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", C.DOCUMENTATION),
    ("2001:db9::1", C.PUBLIC),
    ("2002::1", C.EMBEDDED_IPV4),  # 6to4
    ("2002:ffff::1", C.EMBEDDED_IPV4),
    ("2003::1", C.PUBLIC),
    ("2000::1", C.PUBLIC),
    ("2606:4700::1", C.PUBLIC),
    ("3fff::1", C.DOCUMENTATION),
    ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", C.DOCUMENTATION),
    ("3fff:1000::", C.PUBLIC),
    ("1fff::1", C.RESERVED),
    ("100::1", C.RESERVED),
    ("4000::1", C.RESERVED),
    ("5f00::1", C.RESERVED),
    ("e000::1", C.RESERVED),
    ("fbff::1", C.RESERVED),
    ("fc00::", C.UNIQUE_LOCAL),
    ("fd12:3456::1", C.UNIQUE_LOCAL),
    ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", C.UNIQUE_LOCAL),
    ("fe00::1", C.RESERVED),
    ("fe7f::1", C.RESERVED),
    ("fe80::1", C.LINK_LOCAL_V6),
    ("fe80::1%eth0", C.LINK_LOCAL_V6),
    ("febf:ffff::1", C.LINK_LOCAL_V6),
    ("fec0::1", C.RESERVED),  # deprecated site-local
    ("ff00::1", C.MULTICAST),
    ("ff02::1", C.MULTICAST),
    ("ffff::1", C.MULTICAST),
]


@pytest.mark.parametrize(("text", "expected"), CASES, ids=[t for t, _ in CASES])
def test_class_of_each_address(text: str, expected: C) -> None:
    assert classify(parse_ip(text)) is expected


def test_the_cases_exercise_every_class() -> None:
    assert {expected for _, expected in CASES} == set(C)


def test_policy_groups_partition_the_classes() -> None:
    assert not ALWAYS_REFUSED & DEFAULT_ALLOWED
    assert ALWAYS_REFUSED | DEFAULT_ALLOWED | {C.PUBLIC} == set(C)
    assert policy_text(C.MULTICAST) == "always refused"
    assert policy_text(C.PRIVATE) == "allowed by default"
    assert policy_text(C.PUBLIC).startswith("public: needs --allow-public")


@pytest.mark.parametrize("table", [V4_TABLE, V6_TABLE], ids=["v4", "v6"])
def test_tables_start_with_a_default_block_and_have_no_duplicates(
    table: tuple[tuple[str, C, str], ...],
) -> None:
    assert table[0][0] in {"0.0.0.0/0", "::/0"}
    blocks = [block for block, _, _ in table]
    assert len(blocks) == len(set(blocks))


def test_the_ipv6_default_is_refusal_and_the_ipv4_default_is_public() -> None:
    assert classify(parse_ip("::1:0:0")) is C.RESERVED
    assert classify(parse_ip("1.1.1.1")) is C.PUBLIC


def blocks_of(family: Family) -> list[tuple[int, int]]:
    return [(b.first, b.last) for b in classify_module._BLOCKS[family]]


@pytest.mark.parametrize("family", [Family.IPV4, Family.IPV6])
def test_classes_in_range_matches_classifying_every_address_near_every_boundary(
    family: Family,
) -> None:
    top = (1 << (32 if family is Family.IPV4 else 128)) - 1
    edges = sorted({e for first, last in blocks_of(family) for e in (first, last + 1)})
    checked = 0
    for edge in edges:
        for low in range(edge - 3, edge + 1):
            for high in range(max(low, 0), edge + 4):
                if low < 0 or high > top:
                    continue
                expected = frozenset(classify(Address(family, v)) for v in range(low, high + 1))
                assert classes_in_range(family, low, high) == expected, (low, high)
                checked += 1
    assert checked > 200


def test_classes_in_range_over_whole_spaces_and_single_addresses() -> None:
    assert classes_in_range(Family.IPV4, 0, 2**32 - 1) == {
        C.UNSPECIFIED,
        C.PRIVATE,
        C.LOOPBACK,
        C.LINK_LOCAL_V4,
        C.RESERVED,
        C.DOCUMENTATION,
        C.BENCHMARK,
        C.MULTICAST,
        C.BROADCAST,
        C.PUBLIC,
    }
    assert classes_in_range(Family.IPV6, 0, 2**128 - 1) == {
        C.UNSPECIFIED,
        C.LOOPBACK,
        C.EMBEDDED_IPV4,
        C.PUBLIC,
        C.RESERVED,
        C.BENCHMARK,
        C.DOCUMENTATION,
        C.UNIQUE_LOCAL,
        C.LINK_LOCAL_V6,
        C.MULTICAST,
    }
    one = parse_ip("10.1.2.3").value
    assert classes_in_range(Family.IPV4, one, one) == {C.PRIVATE}


def test_the_generated_table_lists_every_block_in_address_order() -> None:
    lines = table_markdown().splitlines()
    assert lines[0].startswith("| Block")
    assert len(lines) == 2 + len(V4_TABLE) + len(V6_TABLE)
    v4_blocks = [line.split("`")[1] for line in lines[2 : 2 + len(V4_TABLE)]]
    assert v4_blocks[:3] == ["0.0.0.0/0", "0.0.0.0/8", "10.0.0.0/8"]
    assert v4_blocks[-1] == "255.255.255.255/32"
