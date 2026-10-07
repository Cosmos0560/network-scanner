"""Sanitisation of untrusted text (banners, certificate fields, DNS answers).

Everything that comes from the network goes through here when it is captured and again
when it is rendered. Both functions are idempotent.

What is removed:
- ANSI/VT escape sequences (CSI, OSC, DCS/SOS/PM/APC, and two-character escapes),
  including the single-character 8-bit C1 forms.
- Whitespace controls (tab, LF, VT, FF, CR) are replaced by one space so words do not
  merge; every other control character (including NUL and the rest of C0 and C1) is
  dropped.
- Unicode format characters (category Cf: bidi controls, zero-width characters, tag
  characters), line and paragraph separators (Zl, Zp) and lone surrogates (Cs).
"""

from __future__ import annotations

import codecs
import re
import unicodedata
from dataclasses import dataclass

_ANSI = re.compile(
    r"""
    (?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]                        # CSI
  | (?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?   # OSC (to BEL, ST or end)
  | (?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c)?  # DCS SOS PM APC
  | \x1b[ -/]*[0-~]                                         # two-character escapes
    """,
    re.VERBOSE,
)

_SPACE_CONTROLS = frozenset("\t\n\x0b\x0c\r")
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

TRUNCATION_MARK = "..."


@dataclass(frozen=True, slots=True)
class SanitizedText:
    """Result of sanitising: the safe text and whether it was cut to fit a cap."""

    text: str
    truncated: bool


def sanitize_text(text: str, *, max_chars: int) -> SanitizedText:
    """Return `text` with escape sequences and control characters removed.

    Output is at most `max_chars` characters long (the truncation mark included).
    """
    if max_chars < 1:
        raise ValueError("max_chars must be at least 1")
    cleaned: list[str] = []
    for char in _ANSI.sub("", text):
        if char in _SPACE_CONTROLS:
            cleaned.append(" ")
        elif unicodedata.category(char) not in _DROPPED_CATEGORIES:
            cleaned.append(char)
    result = "".join(cleaned)
    if len(result) <= max_chars:
        return SanitizedText(result, False)
    keep = max(max_chars - len(TRUNCATION_MARK), 0)
    marked = (result[:keep] + TRUNCATION_MARK)[:max_chars]
    return SanitizedText(marked, True)


def sanitize_bytes(data: bytes, *, max_bytes: int, max_chars: int) -> SanitizedText:
    """Decode untrusted bytes as UTF-8 and sanitise them.

    At most `max_bytes` are looked at; an incomplete multi-byte sequence cut off by that
    cap is dropped, invalid UTF-8 elsewhere becomes U+FFFD. `truncated` is true when
    either cap was hit.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be at least 1")
    byte_truncated = len(data) > max_bytes
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    decoded = decoder.decode(data[:max_bytes], final=False)
    result = sanitize_text(decoded, max_chars=max_chars)
    return SanitizedText(result.text, byte_truncated or result.truncated)
