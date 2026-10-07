"""Address classes (PLAN.md section 4.2). Pure: integers in, a class out.

The class of an address is that of the most specific block in the tables below that
contains it. Blocks are written as CIDR text and parsed with our own parser at import
time, so a typo in a table fails every test rather than misclassifying quietly.
docs/scope-policy.md carries a generated copy of these tables (`table_markdown`), and a
test keeps the two in step.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

from network_scanner.core.model import AddressClass, Family
from network_scanner.scope.parser import Address, CidrTarget, parse_target

ALWAYS_REFUSED = frozenset(
    {
        AddressClass.UNSPECIFIED,
        AddressClass.MULTICAST,
        AddressClass.BROADCAST,
        AddressClass.RESERVED,
        AddressClass.LINK_LOCAL_V4,
        AddressClass.DOCUMENTATION,
        AddressClass.BENCHMARK,
        AddressClass.EMBEDDED_IPV4,
    }
)
DEFAULT_ALLOWED = frozenset(
    {
        AddressClass.LOOPBACK,
        AddressClass.PRIVATE,
        AddressClass.UNIQUE_LOCAL,
        AddressClass.LINK_LOCAL_V6,
    }
)

# (block, class, note). Most specific block wins, so order does not matter.
V4_TABLE: tuple[tuple[str, AddressClass, str], ...] = (
    (
        "0.0.0.0/0",
        AddressClass.PUBLIC,
        "everything not listed below, including 100.64.0.0/10 (CGNAT, decision D4)",
    ),
    ("0.0.0.0/8", AddressClass.UNSPECIFIED, "this network"),
    ("10.0.0.0/8", AddressClass.PRIVATE, "RFC 1918"),
    ("127.0.0.0/8", AddressClass.LOOPBACK, "loopback"),
    (
        "169.254.0.0/16",
        AddressClass.LINK_LOCAL_V4,
        "includes cloud metadata 169.254.169.254 (decision D4)",
    ),
    ("172.16.0.0/12", AddressClass.PRIVATE, "RFC 1918"),
    ("192.0.0.0/24", AddressClass.RESERVED, "IETF protocol assignments"),
    ("192.0.2.0/24", AddressClass.DOCUMENTATION, "TEST-NET-1"),
    ("192.88.99.0/24", AddressClass.RESERVED, "deprecated 6to4 relay anycast"),
    ("192.168.0.0/16", AddressClass.PRIVATE, "RFC 1918"),
    ("198.18.0.0/15", AddressClass.BENCHMARK, "benchmarking"),
    ("198.51.100.0/24", AddressClass.DOCUMENTATION, "TEST-NET-2"),
    ("203.0.113.0/24", AddressClass.DOCUMENTATION, "TEST-NET-3"),
    ("224.0.0.0/4", AddressClass.MULTICAST, "multicast"),
    ("240.0.0.0/4", AddressClass.RESERVED, "reserved (former class E)"),
    ("255.255.255.255/32", AddressClass.BROADCAST, "limited broadcast"),
)
V6_TABLE: tuple[tuple[str, AddressClass, str], ...] = (
    (
        "::/0",
        AddressClass.RESERVED,
        "everything not listed below: unallocated or special-purpose space",
    ),
    ("::/128", AddressClass.UNSPECIFIED, "unspecified address"),
    ("::1/128", AddressClass.LOOPBACK, "loopback"),
    ("::/96", AddressClass.EMBEDDED_IPV4, "IPv4-compatible (deprecated)"),
    ("::ffff:0:0/96", AddressClass.EMBEDDED_IPV4, "IPv4-mapped"),
    ("::ffff:0:0:0/96", AddressClass.EMBEDDED_IPV4, "IPv4-translated"),
    ("64:ff9b::/96", AddressClass.EMBEDDED_IPV4, "NAT64"),
    ("64:ff9b:1::/48", AddressClass.EMBEDDED_IPV4, "local-use NAT64"),
    ("2000::/3", AddressClass.PUBLIC, "global unicast"),
    ("2001::/23", AddressClass.RESERVED, "IETF protocol assignments"),
    ("2001::/32", AddressClass.EMBEDDED_IPV4, "Teredo"),
    ("2001:2::/48", AddressClass.BENCHMARK, "benchmarking"),
    ("2001:db8::/32", AddressClass.DOCUMENTATION, "documentation"),
    ("2002::/16", AddressClass.EMBEDDED_IPV4, "6to4"),
    ("3fff::/20", AddressClass.DOCUMENTATION, "documentation"),
    ("fc00::/7", AddressClass.UNIQUE_LOCAL, "unique local addresses"),
    ("fe80::/10", AddressClass.LINK_LOCAL_V6, "link-local; the only range that takes a zone id"),
    ("ff00::/8", AddressClass.MULTICAST, "multicast"),
)


@dataclass(frozen=True, slots=True)
class _Block:
    text: str
    first: int
    last: int
    prefix: int
    address_class: AddressClass
    note: str


def _build(table: tuple[tuple[str, AddressClass, str], ...]) -> tuple[_Block, ...]:
    blocks = []
    for text, address_class, note in table:
        target = parse_target(text)
        if not isinstance(target, CidrTarget):  # pragma: no cover  (table typo)
            raise ValueError(f"not a CIDR block: {text}")
        blocks.append(_Block(text, target.first, target.last, target.prefix, address_class, note))
    return tuple(blocks)


_BLOCKS = {Family.IPV4: _build(V4_TABLE), Family.IPV6: _build(V6_TABLE)}


def classify(address: Address) -> AddressClass:
    """The class of the most specific block that contains `address`."""
    blocks = _BLOCKS[address.family]
    best = blocks[0]  # the first block of each table is the /0 that covers everything
    for block in blocks:
        if block.first <= address.value <= block.last and block.prefix > best.prefix:
            best = block
    return best.address_class


@cache
def _segments(family: Family) -> tuple[tuple[int, int, AddressClass], ...]:
    """The address space cut into runs that share one class, in ascending order."""
    blocks = _BLOCKS[family]
    top = (1 << (32 if family is Family.IPV4 else 128)) - 1
    cuts = sorted({0, *(b.first for b in blocks), *(b.last + 1 for b in blocks if b.last < top)})
    segments = []
    for index, start in enumerate(cuts):
        end = cuts[index + 1] - 1 if index + 1 < len(cuts) else top
        segments.append((start, end, classify(Address(family, start))))
    return tuple(segments)


def classes_in_range(family: Family, first: int, last: int) -> frozenset[AddressClass]:
    """Every class that occurs between `first` and `last` inclusive, without iterating."""
    return frozenset(
        address_class
        for start, end, address_class in _segments(family)
        if start <= last and first <= end
    )


def policy_text(address_class: AddressClass) -> str:
    if address_class in ALWAYS_REFUSED:
        return "always refused"
    if address_class in DEFAULT_ALLOWED:
        return "allowed by default"
    return "public: needs --allow-public, a scope-file entry and confirmation"


def table_markdown() -> str:
    """The class tables as Markdown, in address order. Used for docs/scope-policy.md."""
    lines = ["| Block | Class | Policy | Note |", "|-------|-------|--------|------|"]
    for family in (Family.IPV4, Family.IPV6):
        for block in sorted(_BLOCKS[family], key=lambda b: (b.first, b.prefix)):
            lines.append(
                f"| `{block.text}` | `{block.address_class.value}` "
                f"| {policy_text(block.address_class)} | {block.note} |"
            )
    return "\n".join(lines)
