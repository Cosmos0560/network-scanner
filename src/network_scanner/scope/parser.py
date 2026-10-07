"""The closed target grammar (PLAN.md section 4.1).

Everything that is not explicitly accepted is refused. Parsing is done here, by hand:
`ipaddress` and `socket` accept different forms on different Python versions and
platforms (octal and hex IPv4, leading zeros, scope ids), which is exactly what a scope
check must not depend on.

Accepted forms:
- IPv4: four decimal octets 0-255, no leading zeros.
- IPv6: standard text form (RFC 4291, `::` once, optional dotted-quad tail). A zone id
  (`%name`, 1-16 of A-Za-z0-9_.-) is accepted only on fe80::/10. Addresses are returned
  as integers; classification happens in `classify`.
- CIDR: `address/prefix`, host bits must be zero.
- Range: `a.b.c.d-e.f.g.h` or `a.b.c.d-N` (last octet), IPv4 only, start <= end.
- Hostname: ASCII LDH labels 1-63 characters, at most 253 in total, no trailing dot, and
  not shaped like a number (anything `inet_aton` could read as an address is refused).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from network_scanner.core.errors import ReasonCode, ScopeRefusal
from network_scanner.core.limits import MAX_TARGET_CHARS
from network_scanner.core.model import Family, TargetKind, TargetSpec

V4_BITS = 32
V6_BITS = 128
_LINK_LOCAL_V6_TOP10 = 0x3FA  # fe80::/10

_DOT_LOOKALIKES = str.maketrans({chr(0x3002): ".", chr(0xFF0E): ".", chr(0xFF61): "."})  # CJK dots
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})
# What `inet_aton` and friends would read as one component of an address.
_NUMERIC_PART = re.compile(r"0[xX][0-9A-Fa-f]*|[0-9]+")
_NUMERICISH = re.compile(r"[0-9A-Fa-fxX.:/%-]+")
_DEC_OCTET_SHAPE = re.compile(r"[0-9]{1,3}")
_PREFIX = re.compile(r"0|[1-9][0-9]{0,2}")
_ZONE = re.compile(r"[A-Za-z0-9_.-]{1,16}")
_HEX_GROUP = re.compile(r"[0-9A-Fa-f]{1,4}")
_V6_CHARS = frozenset("0123456789abcdefABCDEF:.")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_MAX_HOSTNAME = 253


@dataclass(frozen=True, slots=True)
class Address:
    """A single IP address as an integer. `zone` is set only for fe80::/10."""

    family: Family
    value: int
    zone: str | None = None

    @property
    def bits(self) -> int:
        return V4_BITS if self.family is Family.IPV4 else V6_BITS

    @property
    def text(self) -> str:
        """Canonical text: dotted decimal, or RFC 5952 lower case with the zone if any."""
        if self.family is Family.IPV4:
            return format_v4(self.value)
        text = format_v6(self.value)
        return text if self.zone is None else f"{text}%{self.zone}"

    def sort_key(self) -> tuple[int, int, str]:
        return (0 if self.family is Family.IPV4 else 1, self.value, self.zone or "")


@dataclass(frozen=True, slots=True)
class IpTarget:
    raw: str
    address: Address

    @property
    def spec(self) -> TargetSpec:
        return TargetSpec(self.raw, TargetKind.IP)


@dataclass(frozen=True, slots=True)
class CidrTarget:
    raw: str
    network: Address  # the network address (host bits are zero)
    prefix: int

    @property
    def spec(self) -> TargetSpec:
        return TargetSpec(self.raw, TargetKind.CIDR)

    @property
    def first(self) -> int:
        return self.network.value

    @property
    def last(self) -> int:
        return self.network.value | ((1 << (self.network.bits - self.prefix)) - 1)

    @property
    def skips_network_and_broadcast(self) -> bool:
        """IPv4 networks of /30 and shorter skip the network and broadcast addresses."""
        return self.network.family is Family.IPV4 and self.prefix <= 30


@dataclass(frozen=True, slots=True)
class RangeTarget:
    raw: str
    start: Address
    end: Address

    @property
    def spec(self) -> TargetSpec:
        return TargetSpec(self.raw, TargetKind.RANGE)


@dataclass(frozen=True, slots=True)
class HostnameTarget:
    raw: str
    name: str  # lower case

    @property
    def spec(self) -> TargetSpec:
        return TargetSpec(self.raw, TargetKind.HOSTNAME)


ParsedTarget = IpTarget | CidrTarget | RangeTarget | HostnameTarget


class _Bad(Exception):
    """Internal: a refusal that does not yet know which input string it belongs to."""

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


# -- text <-> integer ---------------------------------------------------------------------


def format_v4(value: int) -> str:
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def format_v6(value: int) -> str:
    """RFC 5952: lower case, no leading zeros, longest run (>= 2) of zero groups as `::`."""
    groups = [(value >> shift) & 0xFFFF for shift in range(112, -16, -16)]
    best_start, best_len = -1, 0
    index = 0
    while index < 8:
        if groups[index] != 0:
            index += 1
            continue
        end = index
        while end < 8 and groups[end] == 0:
            end += 1
        if end - index > best_len:
            best_start, best_len = index, end - index
        index = end
    if best_len < 2:
        return ":".join(f"{group:x}" for group in groups)
    head = ":".join(f"{group:x}" for group in groups[:best_start])
    tail = ":".join(f"{group:x}" for group in groups[best_start + best_len :])
    return f"{head}::{tail}"


def _is_ascii_digits(text: str) -> bool:
    return bool(text) and text.isascii() and text.isdigit()


def _parse_v4(text: str) -> int:
    labels = text.split(".")
    if len(labels) == 4 and all(len(label) <= 3 and _is_ascii_digits(label) for label in labels):
        value = 0
        for label in labels:
            if len(label) > 1 and label[0] == "0":
                raise _Bad(ReasonCode.AMBIGUOUS_NUMERIC, "leading zeros can mean octal")
            octet = int(label)
            if octet > 255:
                raise _Bad(ReasonCode.INVALID_TARGET, "IPv4 octet above 255")
            value = (value << 8) | octet
        return value
    if all(_NUMERIC_PART.fullmatch(label) for label in labels):
        raise _Bad(
            ReasonCode.AMBIGUOUS_NUMERIC,
            "decimal, hex, octal and short IPv4 forms are ambiguous; use a.b.c.d",
        )
    raise _Bad(ReasonCode.INVALID_TARGET, "not a dotted-decimal IPv4 address")


def _parse_v6(text: str) -> int:
    """Parse the address part of an IPv6 literal (no zone, no prefix)."""
    if not text or not set(text) <= _V6_CHARS:
        raise _Bad(ReasonCode.INVALID_TARGET, "not an IPv6 address")
    if "." in text:
        cut = text.rfind(":")
        head, tail = text[: cut + 1], text[cut + 1 :]
        if "." in head or cut < 0:
            raise _Bad(ReasonCode.INVALID_TARGET, "IPv4 tail must be the last part")
        v4 = _parse_v4(tail)
        text = f"{head}{v4 >> 16:x}:{v4 & 0xFFFF:x}"
    if ":::" in text or text.count("::") > 1:
        raise _Bad(ReasonCode.INVALID_TARGET, "'::' may appear only once")
    if "::" in text:
        left_text, right_text = text.split("::")
        left = left_text.split(":") if left_text else []
        right = right_text.split(":") if right_text else []
        if len(left) + len(right) > 7:
            raise _Bad(ReasonCode.INVALID_TARGET, "too many groups")
        missing = 8 - len(left) - len(right)
        groups = [*left, *(["0"] * missing), *right]
    else:
        groups = text.split(":")
        if len(groups) != 8:
            raise _Bad(ReasonCode.INVALID_TARGET, "an IPv6 address has 8 groups")
    value = 0
    for group in groups:
        if not _HEX_GROUP.fullmatch(group):
            raise _Bad(ReasonCode.INVALID_TARGET, "bad IPv6 group")
        value = (value << 16) | int(group, 16)
    return value


def _check_zone(value: int, zone: str) -> None:
    if _ZONE.fullmatch(zone) is None:
        raise _Bad(ReasonCode.INVALID_ZONE_ID, "zone id must be 1-16 of A-Za-z0-9_.-")
    if value >> 118 != _LINK_LOCAL_V6_TOP10:
        raise _Bad(ReasonCode.INVALID_ZONE_ID, "zone ids are accepted only on fe80::/10")


# -- the grammar --------------------------------------------------------------------------


def _check_characters(raw: str) -> None:
    if len(raw) > MAX_TARGET_CHARS:
        raise _Bad(ReasonCode.TARGET_TOO_LONG, f"longer than {MAX_TARGET_CHARS} characters")
    if not raw:
        raise _Bad(ReasonCode.INVALID_TARGET, "empty target")
    for char in raw:
        if unicodedata.category(char) in _REFUSED_CATEGORIES:
            raise _Bad(
                ReasonCode.INVALID_CHARACTERS,
                "whitespace, control and format characters are not allowed",
            )
    if not raw.isascii():
        if any(not c.isascii() and unicodedata.decimal(c, None) is not None for c in raw):
            raise _Bad(ReasonCode.AMBIGUOUS_NUMERIC, "non-ASCII digits are not accepted")
        folded = unicodedata.normalize("NFKC", raw.translate(_DOT_LOOKALIKES))
        if folded.isascii() and _NUMERICISH.fullmatch(folded) and any(c.isdigit() for c in folded):
            raise _Bad(
                ReasonCode.AMBIGUOUS_NUMERIC,
                "non-ASCII digits or dots can normalise to an IP address",
            )
        raise _Bad(ReasonCode.INVALID_HOSTNAME, "non-ASCII is not accepted; use punycode")


def _parse_hostname(raw: str) -> HostnameTarget:
    name = raw.lower()
    if len(name) > _MAX_HOSTNAME:
        raise _Bad(ReasonCode.INVALID_HOSTNAME, f"longer than {_MAX_HOSTNAME} characters")
    labels = name.split(".")
    for label in labels:
        if _LABEL.fullmatch(label) is None:
            raise _Bad(
                ReasonCode.INVALID_HOSTNAME,
                "labels are 1-63 of a-z, 0-9 and '-', not starting or ending with '-'; "
                "empty labels and a trailing dot are refused",
            )
    if _is_ascii_digits(labels[-1]):
        raise _Bad(ReasonCode.AMBIGUOUS_NUMERIC, "the last label of a hostname is all digits")
    return HostnameTarget(raw, name)


def _parse_range(raw: str, left: str, right: str) -> RangeTarget:
    start = _parse_v4(left)
    if "." in right:
        try:
            end = _parse_v4(right)
        except _Bad as bad:
            if bad.reason is ReasonCode.INVALID_TARGET:
                raise _Bad(ReasonCode.INVALID_RANGE, "range end is not an IPv4 address") from None
            raise
    else:
        if not _DEC_OCTET_SHAPE.fullmatch(right):
            raise _Bad(ReasonCode.INVALID_RANGE, "range end must be an IPv4 address or an octet")
        if len(right) > 1 and right[0] == "0":
            raise _Bad(ReasonCode.AMBIGUOUS_NUMERIC, "leading zeros can mean octal")
        if int(right) > 255:
            raise _Bad(ReasonCode.INVALID_RANGE, "range end octet above 255")
        end = (start & 0xFFFFFF00) | int(right)
    if end < start:
        raise _Bad(ReasonCode.INVALID_RANGE, "range is reversed")
    return RangeTarget(raw, Address(Family.IPV4, start), Address(Family.IPV4, end))


def _parse_cidr(raw: str, address_text: str, prefix_text: str) -> CidrTarget:
    if ":" in address_text:
        family, bits, value = Family.IPV6, V6_BITS, _parse_v6(address_text)
    else:
        try:
            family, bits, value = Family.IPV4, V4_BITS, _parse_v4(address_text)
        except _Bad as bad:
            if bad.reason is ReasonCode.INVALID_TARGET:
                raise _Bad(
                    ReasonCode.INVALID_CIDR, "a prefix is valid only on an IP address"
                ) from None
            raise
    if _PREFIX.fullmatch(prefix_text) is None:
        raise _Bad(ReasonCode.INVALID_CIDR, "prefix must be a decimal number without sign")
    prefix = int(prefix_text)
    if prefix > bits:
        raise _Bad(ReasonCode.INVALID_CIDR, f"prefix is larger than {bits}")
    if value & ((1 << (bits - prefix)) - 1):
        raise _Bad(ReasonCode.CIDR_HOST_BITS, "host bits are set; write the network address")
    return CidrTarget(raw, Address(family, value), prefix)


def _parse_colon_target(raw: str) -> ParsedTarget:
    address_text, has_zone, zone = raw.partition("%")
    if "/" in address_text:
        if has_zone:
            raise _Bad(ReasonCode.INVALID_CIDR, "zone ids are not accepted in a CIDR")
        left, _, prefix_text = address_text.partition("/")
        return _parse_cidr(raw, left, prefix_text)
    if "-" in address_text:
        raise _Bad(ReasonCode.INVALID_RANGE, "IPv6 ranges are not supported")
    value = _parse_v6(address_text)
    if has_zone:
        _check_zone(value, zone)
    return IpTarget(raw, Address(Family.IPV6, value, zone if has_zone else None))


def _parse_plain_target(raw: str) -> ParsedTarget:
    if "-" in raw:
        left, _, right = raw.partition("-")
        left_labels = left.split(".")
        if len(left_labels) >= 2 and all(_NUMERIC_PART.fullmatch(label) for label in left_labels):
            return _parse_range(raw, left, right)
    labels = raw.split(".")
    if len(labels) == 4 and all(len(label) <= 3 and _is_ascii_digits(label) for label in labels):
        return IpTarget(raw, Address(Family.IPV4, _parse_v4(raw)))
    if all(_NUMERIC_PART.fullmatch(label) for label in labels):
        raise _Bad(
            ReasonCode.AMBIGUOUS_NUMERIC,
            "decimal, hex, octal and short IPv4 forms are ambiguous; use a.b.c.d",
        )
    return _parse_hostname(raw)


def _parse(raw: str) -> ParsedTarget:
    _check_characters(raw)
    if ":" in raw:
        return _parse_colon_target(raw)
    if "/" in raw:
        left, _, prefix_text = raw.partition("/")
        return _parse_cidr(raw, left, prefix_text)
    return _parse_plain_target(raw)


def parse_target(raw: str) -> ParsedTarget:
    """Parse one target string, or raise `ScopeRefusal` with a stable reason code."""
    try:
        return _parse(raw)
    except _Bad as bad:
        raise ScopeRefusal(bad.reason, raw, bad.detail) from None


def parse_ip(raw: str) -> Address:
    """Parse exactly one IP address literal (not a CIDR, range or hostname)."""
    target = parse_target(raw)
    if not isinstance(target, IpTarget):
        raise ScopeRefusal(ReasonCode.INVALID_TARGET, raw, "expected a single IP address")
    return target.address


# -- sizes and expansion ------------------------------------------------------------------


def count_addresses(target: ParsedTarget) -> int:
    """How many addresses `target` stands for, computed arithmetically (nothing is expanded)."""
    if isinstance(target, CidrTarget):
        size = 1 << (target.network.bits - target.prefix)
        return size - 2 if target.skips_network_and_broadcast else size
    if isinstance(target, RangeTarget):
        return target.end.value - target.start.value + 1
    return 1


def expand(target: IpTarget | CidrTarget | RangeTarget) -> Iterator[Address]:
    """Yield the addresses of a target in ascending order. Check `count_addresses` first."""
    if isinstance(target, IpTarget):
        yield target.address
        return
    if isinstance(target, RangeTarget):
        first, last, family = target.start.value, target.end.value, Family.IPV4
    else:
        first, last, family = target.first, target.last, target.network.family
        if target.skips_network_and_broadcast:
            first, last = first + 1, last - 1
    for value in range(first, last + 1):
        yield Address(family, value)
