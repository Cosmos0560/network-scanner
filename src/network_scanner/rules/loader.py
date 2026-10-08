"""Loading rule files: the packaged built-in rules and files named by the user.

A user file is size-capped while it is read (at most the cap plus one byte is read), must be
a regular file, and must be UTF-8. Everything after that is `parse_fingerprint_rules`.
"""

from __future__ import annotations

import stat
from functools import cache
from importlib.resources import files
from pathlib import Path

from network_scanner.core.limits import MAX_RULE_FILE_BYTES
from network_scanner.rules.schema import (
    FILE,
    RuleError,
    RuleErrorCode,
    RuleSet,
    parse_fingerprint_rules,
)

BUILTIN_FINGERPRINTS = "fingerprints.yaml"


def _decode(data: bytes) -> str:
    if len(data) > MAX_RULE_FILE_BYTES:
        raise RuleError(
            RuleErrorCode.FILE_TOO_LARGE, FILE, f"larger than {MAX_RULE_FILE_BYTES} bytes"
        )
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise RuleError(RuleErrorCode.NOT_UTF8, FILE, "the file is not valid UTF-8") from None


def load_fingerprint_rules(path: Path) -> RuleSet:
    """Read and validate a rule file. Only a regular file is opened."""
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise RuleError(RuleErrorCode.NOT_A_FILE, FILE, "not a regular file")
        with path.open("rb") as handle:
            data = handle.read(MAX_RULE_FILE_BYTES + 1)
    except OSError as exc:
        raise RuleError(
            RuleErrorCode.UNREADABLE, FILE, f"cannot read the file ({type(exc).__name__})"
        ) from None
    return parse_fingerprint_rules(_decode(data))


@cache
def builtin_fingerprint_rules() -> RuleSet:
    """The rules shipped inside the package."""
    resource = files("network_scanner.rules") / "data" / BUILTIN_FINGERPRINTS
    try:
        data = resource.read_bytes()
    except OSError:
        raise RuleError(
            RuleErrorCode.UNREADABLE, FILE, "the built-in rule file is missing"
        ) from None
    return parse_fingerprint_rules(_decode(data))
