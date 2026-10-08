"""The fingerprint rule schema: strict, closed, and validated field by field.

A rule file is a YAML mapping with exactly the keys `schema_version` and `rules`. Every rule
has exactly the keys `id`, `service`, `confidence`, `description` and `match`; `match` has
one to four of `banner_regex`, `http_server_regex`, `http_response` and `tls`, all of which
must hold for the rule to apply. Unknown keys, missing keys, wrong types, duplicate ids and
regular expressions outside the safe subset (see `regex_safety.py`) are refused, each with
the location of the problem and a stable error code. Nothing here reads a file.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, TypeVar

from network_scanner.core.errors import NetworkScannerError
from network_scanner.core.limits import MAX_RULE_FILE_BYTES, MAX_RULES
from network_scanner.core.model import Confidence
from network_scanner.core.sanitize import sanitize_text
from network_scanner.core.yamlsafe import safe_load_document
from network_scanner.rules.regex_safety import UnsafeRegex, compile_safe

SCHEMA_VERSION = 1


class _HasId(Protocol):
    @property
    def id(self) -> str: ...


_R = TypeVar("_R", bound=_HasId)
FILE = "<file>"
_ID = re.compile(r"[a-z][a-z0-9-]{0,47}")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_TOP_KEYS = ("schema_version", "rules")
_RULE_KEYS = ("id", "service", "confidence", "description", "match")
_MATCH_KEYS = ("banner_regex", "http_server_regex", "http_response", "tls")
_MAX_DESCRIPTION = 200


class RuleErrorCode(StrEnum):
    FILE_TOO_LARGE = "file_too_large"
    NOT_UTF8 = "not_utf8"
    UNREADABLE = "unreadable"
    NOT_A_FILE = "not_a_file"
    INVALID_YAML = "invalid_yaml"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNKNOWN_KEY = "unknown_key"
    MISSING_KEY = "missing_key"
    WRONG_TYPE = "wrong_type"
    INVALID_VALUE = "invalid_value"
    TOO_MANY_RULES = "too_many_rules"
    DUPLICATE_ID = "duplicate_id"
    UNSAFE_REGEX = "unsafe_regex"
    EMPTY_MATCH = "empty_match"


class RuleError(NetworkScannerError):
    """A rule file is unreadable or invalid. `location` says where, `code` says what."""

    def __init__(self, code: RuleErrorCode, location: str, detail: str) -> None:
        self.code = code
        self.location = location
        self.detail = detail
        super().__init__(f"{location}: {code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class FingerprintRule:
    """One validated rule. The compiled patterns are not part of its identity."""

    id: str
    service: str
    confidence: Confidence
    description: str
    banner_regex: str | None
    http_server_regex: str | None
    http_response: bool
    tls: bool
    banner_pattern: re.Pattern[str] | None = field(default=None, compare=False, repr=False)
    http_server_pattern: re.Pattern[str] | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[FingerprintRule, ...]


def shown(name: object) -> str:
    return repr(sanitize_text(str(name), max_chars=40).text)


def mapping(value: Any, location: str, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuleError(RuleErrorCode.WRONG_TYPE, location, "expected a mapping")
    for key in value:
        if key not in keys:
            where = location
            if isinstance(key, str) and key.isidentifier():
                where = key if location == FILE else f"{location}.{key}"
            raise RuleError(RuleErrorCode.UNKNOWN_KEY, where, f"unknown key {shown(key)}")
    return value


def require(mapping: dict[str, Any], location: str, keys: tuple[str, ...]) -> None:
    for key in keys:
        if key not in mapping:
            raise RuleError(RuleErrorCode.MISSING_KEY, location, f"missing key {key!r}")


def text_value(
    value: Any, location: str, *, pattern: re.Pattern[str] | None, max_chars: int
) -> str:
    if not isinstance(value, str):
        raise RuleError(RuleErrorCode.WRONG_TYPE, location, "expected a string")
    if not 1 <= len(value) <= max_chars:
        raise RuleError(
            RuleErrorCode.INVALID_VALUE, location, f"must be 1-{max_chars} characters long"
        )
    if any(unicodedata.category(char) in _REFUSED_CATEGORIES for char in value):
        raise RuleError(RuleErrorCode.INVALID_VALUE, location, "contains control characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise RuleError(RuleErrorCode.INVALID_VALUE, location, f"must match {pattern.pattern}")
    return value


def regex_value(value: Any, location: str) -> tuple[str, re.Pattern[str]]:
    if not isinstance(value, str):
        raise RuleError(RuleErrorCode.WRONG_TYPE, location, "expected a string")
    try:
        return value, compile_safe(value)
    except UnsafeRegex as exc:
        raise RuleError(RuleErrorCode.UNSAFE_REGEX, location, str(exc)) from None


def _rule(raw: Any, location: str) -> FingerprintRule:
    rule = mapping(raw, location, _RULE_KEYS)
    require(rule, location, _RULE_KEYS)
    rule_id = text_value(rule["id"], f"{location}.id", pattern=_ID, max_chars=48)
    service = text_value(rule["service"], f"{location}.service", pattern=_SERVICE, max_chars=32)
    confidence_text = text_value(
        rule["confidence"], f"{location}.confidence", pattern=None, max_chars=16
    )
    try:
        confidence = Confidence(confidence_text)
    except ValueError:
        choices = ", ".join(c.value for c in Confidence)
        raise RuleError(
            RuleErrorCode.INVALID_VALUE, f"{location}.confidence", f"must be one of {choices}"
        ) from None
    description = text_value(
        rule["description"], f"{location}.description", pattern=None, max_chars=_MAX_DESCRIPTION
    )

    match_location = f"{location}.match"
    match = mapping(rule["match"], match_location, _MATCH_KEYS)
    if not match:
        raise RuleError(
            RuleErrorCode.EMPTY_MATCH, match_location, "a rule needs at least one condition"
        )
    banner_regex = banner_pattern = server_regex = server_pattern = None
    if "banner_regex" in match:
        banner_regex, banner_pattern = regex_value(
            match["banner_regex"], f"{match_location}.banner_regex"
        )
    if "http_server_regex" in match:
        server_regex, server_pattern = regex_value(
            match["http_server_regex"], f"{match_location}.http_server_regex"
        )
    for name in ("http_response", "tls"):
        if name not in match:
            continue
        if not isinstance(match[name], bool):
            raise RuleError(
                RuleErrorCode.WRONG_TYPE, f"{match_location}.{name}", "expected a boolean"
            )
        if not match[name]:
            raise RuleError(
                RuleErrorCode.INVALID_VALUE,
                f"{match_location}.{name}",
                "must be true; leave the condition out instead of setting it to false",
            )
    return FingerprintRule(
        id=rule_id,
        service=service,
        confidence=confidence,
        description=description,
        banner_regex=banner_regex,
        http_server_regex=server_regex,
        http_response="http_response" in match,
        tls="tls" in match,
        banner_pattern=banner_pattern,
        http_server_pattern=server_pattern,
    )


def parse_rule_document(text: str, parse_rule: Callable[[Any, str], _R]) -> list[_R]:
    """Validate the envelope of a rule document and parse each rule with `parse_rule`.

    The envelope is the size cap, safe YAML, exactly the keys `schema_version` and `rules`,
    the version, the list bounds, and unique ids (every rule needs an `id` attribute).
    """
    if len(text.encode("utf-8", "surrogatepass")) > MAX_RULE_FILE_BYTES:
        raise RuleError(
            RuleErrorCode.FILE_TOO_LARGE, FILE, f"larger than {MAX_RULE_FILE_BYTES} bytes"
        )

    def invalid_yaml(message: str) -> RuleError:
        return RuleError(RuleErrorCode.INVALID_YAML, FILE, message)

    document = safe_load_document(text, error=invalid_yaml)
    top = mapping(document, FILE, _TOP_KEYS)
    require(top, FILE, _TOP_KEYS)
    version = top["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise RuleError(RuleErrorCode.WRONG_TYPE, "schema_version", "expected an integer")
    if version != SCHEMA_VERSION:
        raise RuleError(
            RuleErrorCode.UNSUPPORTED_VERSION,
            "schema_version",
            f"only version {SCHEMA_VERSION} is supported, not {version}",
        )
    raw_rules = top["rules"]
    if not isinstance(raw_rules, list):
        raise RuleError(RuleErrorCode.WRONG_TYPE, "rules", "expected a list")
    if not raw_rules:
        raise RuleError(RuleErrorCode.INVALID_VALUE, "rules", "the list is empty")
    if len(raw_rules) > MAX_RULES:
        raise RuleError(RuleErrorCode.TOO_MANY_RULES, "rules", f"more than {MAX_RULES} rules")

    rules: list[_R] = []
    first_use: dict[str, int] = {}
    for index, raw in enumerate(raw_rules):
        rule = parse_rule(raw, f"rules[{index}]")
        if rule.id in first_use:
            raise RuleError(
                RuleErrorCode.DUPLICATE_ID,
                f"rules[{index}].id",
                f"id {rule.id!r} is already used by rules[{first_use[rule.id]}]",
            )
        first_use[rule.id] = index
        rules.append(rule)
    return rules


def parse_fingerprint_rules(text: str) -> RuleSet:
    """Validate one fingerprint rule document and return its rules, in file order."""
    return RuleSet(tuple(parse_rule_document(text, _rule)))
