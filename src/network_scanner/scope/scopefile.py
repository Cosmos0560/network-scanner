"""The scope file (PLAN.md section 4.3): the allow-list for public addresses.

Plain UTF-8 text, one IP or CIDR literal per line, `#` starts a comment. No hostnames, no
ranges, no zone ids. Public entries are no wider than /24 (IPv4) or /120 (IPv6), and an
entry may not cover any always-refused address, so the file can never be mistaken for a
way to unlock those. Size cap 64 KB. Entries go through the same closed parser as targets.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from network_scanner.core.errors import ScopeFileError, ScopeRefusal
from network_scanner.core.limits import MAX_SCOPE_ENTRIES, MAX_SCOPE_FILE_BYTES
from network_scanner.core.model import AddressClass, Family
from network_scanner.core.sanitize import sanitize_text
from network_scanner.scope.classify import ALWAYS_REFUSED, classes_in_range
from network_scanner.scope.parser import Address, CidrTarget, IpTarget, parse_target

MAX_PUBLIC_PREFIX_V4 = 24
MAX_PUBLIC_PREFIX_V6 = 120
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})
_ADDRESS_SPACE_END = 1 << 129  # above any IPv4 or IPv6 value


@dataclass(frozen=True, slots=True)
class ScopeEntry:
    raw: str
    family: Family
    first: int
    last: int


@dataclass(frozen=True, slots=True)
class ScopeFile:
    entries: tuple[ScopeEntry, ...]
    merged_v4: tuple[tuple[int, int], ...]
    merged_v6: tuple[tuple[int, int], ...]

    @classmethod
    def of(cls, entries: Iterable[ScopeEntry]) -> ScopeFile:
        kept = tuple(entries)
        return cls(
            kept,
            _merge(e for e in kept if e.family is Family.IPV4),
            _merge(e for e in kept if e.family is Family.IPV6),
        )

    def contains(self, address: Address) -> bool:
        intervals = self.merged_v4 if address.family is Family.IPV4 else self.merged_v6
        position = bisect_right(intervals, (address.value, _ADDRESS_SPACE_END))
        return (
            position > 0
            and intervals[position - 1][0] <= address.value <= intervals[position - 1][1]
        )


def _merge(entries: Iterable[ScopeEntry]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for first, last in sorted((e.first, e.last) for e in entries):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return tuple(merged)


def _entry(content: str, line: int) -> ScopeEntry:
    try:
        target = parse_target(content)
    except ScopeRefusal as refusal:
        raise ScopeFileError(f"{refusal.reason_code.value}: {refusal.detail}", line=line) from None
    if isinstance(target, IpTarget):
        address = target.address
        if address.zone is not None:
            raise ScopeFileError("zone ids are not accepted in the scope file", line=line)
        family, first, last, prefix = address.family, address.value, address.value, address.bits
    elif isinstance(target, CidrTarget):
        family, first, last, prefix = (
            target.network.family,
            target.first,
            target.last,
            target.prefix,
        )
    else:
        raise ScopeFileError("only IP addresses and CIDR blocks are accepted", line=line)

    classes = classes_in_range(family, first, last)
    refused = sorted(c.value for c in classes & ALWAYS_REFUSED)
    if refused:
        raise ScopeFileError(
            f"entry covers always-refused addresses ({', '.join(refused)})", line=line
        )
    limit = MAX_PUBLIC_PREFIX_V4 if family is Family.IPV4 else MAX_PUBLIC_PREFIX_V6
    if AddressClass.PUBLIC in classes and prefix < limit:
        raise ScopeFileError(
            f"public entries must be /{limit} or narrower, not /{prefix}", line=line
        )
    return ScopeEntry(content, family, first, last)


def parse_scope_text(text: str) -> ScopeFile:
    entries: list[ScopeEntry] = []
    for number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        for char in line:
            if char not in " \t" and unicodedata.category(char) in _REFUSED_CATEGORIES:
                shown = sanitize_text(line, max_chars=60).text
                raise ScopeFileError(f"control or format character in {shown!r}", line=number)
        content = line.split("#", 1)[0].strip(" \t")
        if not content:
            continue
        if " " in content or "\t" in content:
            raise ScopeFileError("one entry per line, without spaces", line=number)
        if len(entries) >= MAX_SCOPE_ENTRIES:
            raise ScopeFileError(f"more than {MAX_SCOPE_ENTRIES} entries", line=number)
        entries.append(_entry(content, number))
    return ScopeFile.of(entries)


def parse_scope_bytes(data: bytes) -> ScopeFile:
    if len(data) > MAX_SCOPE_FILE_BYTES:
        raise ScopeFileError(f"larger than {MAX_SCOPE_FILE_BYTES} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ScopeFileError("not valid UTF-8") from None
    return parse_scope_text(text)


def load_scope_file(path: Path) -> ScopeFile:
    """Read and parse a scope file, reading at most the size cap plus one byte."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SCOPE_FILE_BYTES + 1)
    except OSError as exc:
        raise ScopeFileError(f"cannot read the scope file ({type(exc).__name__})") from None
    return parse_scope_bytes(data)
