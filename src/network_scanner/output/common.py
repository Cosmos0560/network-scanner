"""Shared by every renderer: text that came from the network is sanitised again on the way out.

Banners, HTTP headers and certificate fields were sanitised when they were captured. They are
sanitised once more here, in every output format, so that a bug upstream (or a report built by
hand) still cannot put an escape sequence, a bidirectional control or a NUL into a terminal, a
log shipper or a spreadsheet. Both functions are idempotent. A string longer than
`MAX_OUTPUT_STRING_CHARS` is cut.
"""

from __future__ import annotations

from typing import Any

from network_scanner.core.limits import MAX_OUTPUT_STRING_CHARS
from network_scanner.core.model import Severity, to_jsonable
from network_scanner.core.sanitize import sanitize_text


def clean(text: str, *, max_chars: int = MAX_OUTPUT_STRING_CHARS) -> str:
    return sanitize_text(text, max_chars=max_chars).text


def clean_tree(value: Any) -> Any:
    """Sanitise every string (keys included) in a structure made of dicts, lists and scalars."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        return {clean(str(key)): clean_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean_tree(item) for item in value]
    return value


def jsonable(value: Any) -> Any:
    """The model value as plain JSON types, with every string sanitised."""
    return clean_tree(to_jsonable(value))


def severity_counts(severities: list[Severity]) -> str:
    """'medium: 2, info: 1' from the most severe down; an empty string for none."""
    parts = []
    for severity in sorted(set(severities), key=lambda s: -s.rank):
        parts.append(f"{severity.value}: {severities.count(severity)}")
    return ", ".join(parts)
