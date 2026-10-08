"""Loading rule files: the packaged built-in rules and files named by the user.

A user file is size-capped while it is read (at most the cap plus one byte is read), must be
a regular file, and must be UTF-8. Everything after that is the schema check of the rule kind.
"""

from __future__ import annotations

import stat
from functools import cache
from importlib.resources import files
from pathlib import Path

from network_scanner.core.limits import MAX_RULE_FILE_BYTES
from network_scanner.rules.findings_schema import FindingRuleSet, parse_finding_rules
from network_scanner.rules.schema import (
    FILE,
    RuleError,
    RuleErrorCode,
    RuleSet,
    parse_fingerprint_rules,
)

BUILTIN_FINGERPRINTS = "fingerprints.yaml"
BUILTIN_FINDINGS = "findings.yaml"


def _decode(data: bytes) -> str:
    if len(data) > MAX_RULE_FILE_BYTES:
        raise RuleError(
            RuleErrorCode.FILE_TOO_LARGE, FILE, f"larger than {MAX_RULE_FILE_BYTES} bytes"
        )
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise RuleError(RuleErrorCode.NOT_UTF8, FILE, "the file is not valid UTF-8") from None


def _read(path: Path) -> str:
    """Read a rule file: a regular file only, at most the size cap plus one byte."""
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise RuleError(RuleErrorCode.NOT_A_FILE, FILE, "not a regular file")
        with path.open("rb") as handle:
            data = handle.read(MAX_RULE_FILE_BYTES + 1)
    except OSError as exc:
        raise RuleError(
            RuleErrorCode.UNREADABLE, FILE, f"cannot read the file ({type(exc).__name__})"
        ) from None
    return _decode(data)


def _builtin(name: str) -> str:
    resource = files("network_scanner.rules") / "data" / name
    try:
        data = resource.read_bytes()
    except OSError:
        raise RuleError(
            RuleErrorCode.UNREADABLE, FILE, "the built-in rule file is missing"
        ) from None
    return _decode(data)


def load_fingerprint_rules(path: Path) -> RuleSet:
    """Read and validate a fingerprint rule file."""
    return parse_fingerprint_rules(_read(path))


def load_finding_rules(path: Path) -> FindingRuleSet:
    """Read and validate a finding rule file."""
    return parse_finding_rules(_read(path))


@cache
def builtin_fingerprint_rules() -> RuleSet:
    """The fingerprint rules shipped inside the package."""
    return parse_fingerprint_rules(_builtin(BUILTIN_FINGERPRINTS))


@cache
def builtin_finding_rules() -> FindingRuleSet:
    """The finding rules shipped inside the package."""
    return parse_finding_rules(_builtin(BUILTIN_FINDINGS))
