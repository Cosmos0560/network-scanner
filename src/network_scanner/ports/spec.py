"""Port specifications: lists, ranges and preset names (PLAN.md section 2, Phase 2).

Grammar (strict, no spaces): a comma-separated list of items, each one of
- a port: 1-65535, decimal, no leading zeros (`080` is refused as ambiguous);
- a range: `low-high`, both ports, low <= high;
- a preset name: lower-case, for example `common`.

The number of distinct ports is computed by merging intervals, before anything is
expanded, so `1-65535,1-65535,...` cannot allocate more than the cap allows.
"""

from __future__ import annotations

import re
import unicodedata
from enum import StrEnum

from network_scanner.core.errors import UsageError
from network_scanner.core.limits import MAX_PORT_SPEC_CHARS
from network_scanner.ports.presets import PRESET_NAMES, load_preset

MAX_PORT = 65535
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})


class PortErrorCode(StrEnum):
    EMPTY_SPEC = "empty_spec"
    SPEC_TOO_LONG = "spec_too_long"
    INVALID_CHARACTERS = "invalid_characters"
    EMPTY_ITEM = "empty_item"
    INVALID_PORT = "invalid_port"
    INVALID_RANGE = "invalid_range"
    UNKNOWN_PRESET = "unknown_preset"
    TOO_MANY_PORTS = "too_many_ports"


class PortSpecError(UsageError):
    def __init__(self, code: PortErrorCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


def _port(text: str) -> int:
    if _PORT.fullmatch(text) is None or int(text) > MAX_PORT:
        raise PortSpecError(
            PortErrorCode.INVALID_PORT, "ports are decimal 1-65535 without leading zeros"
        )
    return int(text)


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for low, high in sorted(intervals):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def parse_ports(text: str, *, max_ports: int) -> tuple[int, ...]:
    """Parse a port specification into ascending, distinct ports, at most `max_ports`."""
    if len(text) > MAX_PORT_SPEC_CHARS:
        raise PortSpecError(
            PortErrorCode.SPEC_TOO_LONG, f"longer than {MAX_PORT_SPEC_CHARS} characters"
        )
    if not text:
        raise PortSpecError(PortErrorCode.EMPTY_SPEC, "no ports were given")
    if not text.isascii() or any(unicodedata.category(c) in _REFUSED_CATEGORIES for c in text):
        raise PortSpecError(
            PortErrorCode.INVALID_CHARACTERS, "only ASCII without spaces or control characters"
        )

    intervals: list[tuple[int, int]] = []
    for item in text.split(","):
        if not item:
            raise PortSpecError(PortErrorCode.EMPTY_ITEM, "empty item in the port list")
        if _NAME.fullmatch(item):
            if item not in PRESET_NAMES:
                raise PortSpecError(PortErrorCode.UNKNOWN_PRESET, f"unknown preset {item!r}")
            intervals.extend((port, port) for port in load_preset(item).ports)
        elif "-" in item:
            low_text, _, high_text = item.partition("-")
            try:
                low, high = _port(low_text), _port(high_text)
            except PortSpecError:
                raise PortSpecError(
                    PortErrorCode.INVALID_RANGE, "a range is two ports joined by one '-'"
                ) from None
            if low > high:
                raise PortSpecError(PortErrorCode.INVALID_RANGE, "range is reversed")
            intervals.append((low, high))
        else:
            port = _port(item)
            intervals.append((port, port))

    merged = _merge(intervals)
    if sum(high - low + 1 for low, high in merged) > max_ports:
        raise PortSpecError(PortErrorCode.TOO_MANY_PORTS, f"more than {max_ports} distinct ports")
    return tuple(port for low, high in merged for port in range(low, high + 1))
