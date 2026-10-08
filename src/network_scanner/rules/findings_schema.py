"""The finding rule schema: strict, closed, validated field by field.

A finding rule file has the same envelope as a fingerprint rule file (exactly the keys
`schema_version` and `rules`; see `schema.py`). A rule has exactly `id`, `title`, `severity`,
`confidence`, `description`, `evidence`, `when` and, optionally, `references`.

- `severity` and `confidence` are separate: severity says how much the finding would matter if
  it is right, confidence says how sure the evidence makes us. `confidence` is `low`, `medium`,
  `high`, or `from_service`, which takes the confidence of the fingerprint rule that named the
  service (only for a rule that has `when.service`).
- `when` has one or more conditions, all of which must hold: `service` (a service name),
  `tls_version_in` (a list of protocol versions), and the flags `tls_expired`,
  `tls_hostname_mismatch`, `tls_self_issued` and `tls_unreadable`, each of which must be `true`.
- `evidence` is a template. `{name}` is replaced by a fact about the port taken from a closed
  list (`EVIDENCE_FIELDS`); any other brace is refused. Every finding carries its evidence.
- `references` are CWE ids and RFC numbers only (`CWE-319`, `RFC 5280`, optionally with a
  section), and only where the reference is precise. There is no ATT&CK mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, TypeVar

from network_scanner.core.model import Confidence, Severity
from network_scanner.rules.schema import (
    RuleError,
    RuleErrorCode,
    mapping,
    parse_rule_document,
    require,
    text_value,
)

_E = TypeVar("_E", Severity, Confidence)
_ID = re.compile(r"[a-z][a-z0-9-]{0,47}")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_VERSION = re.compile(r"[A-Za-z0-9.]{1,16}")
_REFERENCE = re.compile(
    r"(?:CWE-[0-9]{1,5}|RFC [0-9]{1,5}(?: section [0-9]{1,2}(?:\.[0-9]{1,2}){0,3})?)"
)
_PLACEHOLDER = re.compile(r"\{([a-z_0-9]+)\}")
_RULE_KEYS = ("id", "title", "severity", "confidence", "description", "evidence", "when")
_OPTIONAL_KEYS = ("references",)
_WHEN_KEYS = (
    "service",
    "tls_version_in",
    "tls_expired",
    "tls_hostname_mismatch",
    "tls_self_issued",
    "tls_unreadable",
)
_FLAGS = ("tls_expired", "tls_hostname_mismatch", "tls_self_issued", "tls_unreadable")
FROM_SERVICE = "from_service"
MAX_EVIDENCE_TEMPLATE = 400
MAX_REFERENCES = 4
MAX_VERSIONS = 8

# Facts a finding's evidence can mention. All text comes from the network and has already been
# sanitised when captured; the evaluator sanitises the finished evidence again.
EVIDENCE_FIELDS = frozenset(
    {
        "address",
        "port",
        "service",
        "service_rule",
        "service_confidence",
        "banner",
        "http_server",
        "tls_version",
        "tls_cipher",
        "tls_subject",
        "tls_issuer",
        "tls_san",
        "tls_not_before",
        "tls_not_after",
        "tls_self_issued",
        "tls_self_signature_valid",
        "tls_expired",
        "tls_hostname_match",
        "tls_sha256",
        "tls_parse_error",
    }
)


@dataclass(frozen=True, slots=True)
class FindingRule:
    id: str
    title: str
    severity: Severity
    confidence: Confidence | None  # None: take the confidence of the matched service
    description: str
    evidence: str
    references: tuple[str, ...]
    service: str | None
    tls_versions: tuple[str, ...]
    tls_expired: bool
    tls_hostname_mismatch: bool
    tls_self_issued: bool
    tls_unreadable: bool


@dataclass(frozen=True, slots=True)
class FindingRuleSet:
    rules: tuple[FindingRule, ...]


def _choice(value: Any, location: str, kind: type[_E]) -> _E:
    text = text_value(value, location, pattern=None, max_chars=16)
    try:
        return kind(text)
    except ValueError:
        choices = ", ".join(member.value for member in kind)
        raise RuleError(
            RuleErrorCode.INVALID_VALUE, location, f"must be one of {choices}"
        ) from None


def _evidence(value: Any, location: str) -> str:
    template = text_value(value, location, pattern=None, max_chars=MAX_EVIDENCE_TEMPLATE)
    names = _PLACEHOLDER.findall(template)
    unknown = sorted(set(names) - EVIDENCE_FIELDS)
    if unknown:
        raise RuleError(
            RuleErrorCode.INVALID_VALUE, location, f"unknown evidence field {{{unknown[0]}}}"
        )
    if "{" in _PLACEHOLDER.sub("", template) or "}" in _PLACEHOLDER.sub("", template):
        raise RuleError(
            RuleErrorCode.INVALID_VALUE,
            location,
            "a brace that is not part of a {field} is not allowed",
        )
    return template


def _references(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RuleError(RuleErrorCode.WRONG_TYPE, location, "expected a list")
    if len(value) > MAX_REFERENCES:
        raise RuleError(
            RuleErrorCode.INVALID_VALUE, location, f"more than {MAX_REFERENCES} entries"
        )
    return tuple(
        text_value(item, f"{location}[{index}]", pattern=_REFERENCE, max_chars=40)
        for index, item in enumerate(value)
    )


def _versions(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RuleError(RuleErrorCode.WRONG_TYPE, location, "expected a list")
    if not 1 <= len(value) <= MAX_VERSIONS:
        raise RuleError(RuleErrorCode.INVALID_VALUE, location, f"expected 1-{MAX_VERSIONS} entries")
    return tuple(
        text_value(item, f"{location}[{index}]", pattern=_VERSION, max_chars=16)
        for index, item in enumerate(value)
    )


def _rule(raw: Any, location: str) -> FindingRule:
    rule = mapping(raw, location, (*_RULE_KEYS, *_OPTIONAL_KEYS))
    require(rule, location, _RULE_KEYS)
    rule_id = text_value(rule["id"], f"{location}.id", pattern=_ID, max_chars=48)
    title = text_value(rule["title"], f"{location}.title", pattern=None, max_chars=120)
    severity = _choice(rule["severity"], f"{location}.severity", Severity)
    description = text_value(
        rule["description"], f"{location}.description", pattern=None, max_chars=300
    )
    evidence = _evidence(rule["evidence"], f"{location}.evidence")
    references = (
        _references(rule["references"], f"{location}.references") if "references" in rule else ()
    )

    when_location = f"{location}.when"
    when = mapping(rule["when"], when_location, _WHEN_KEYS)
    if not when:
        raise RuleError(
            RuleErrorCode.EMPTY_MATCH, when_location, "a rule needs at least one condition"
        )
    service = (
        text_value(when["service"], f"{when_location}.service", pattern=_SERVICE, max_chars=32)
        if "service" in when
        else None
    )
    versions = (
        _versions(when["tls_version_in"], f"{when_location}.tls_version_in")
        if "tls_version_in" in when
        else ()
    )
    for name in _FLAGS:
        if name not in when:
            continue
        if not isinstance(when[name], bool):
            raise RuleError(
                RuleErrorCode.WRONG_TYPE, f"{when_location}.{name}", "expected a boolean"
            )
        if not when[name]:
            raise RuleError(
                RuleErrorCode.INVALID_VALUE,
                f"{when_location}.{name}",
                "must be true; leave the condition out instead of setting it to false",
            )

    confidence_text = text_value(
        rule["confidence"], f"{location}.confidence", pattern=None, max_chars=16
    )
    confidence: Confidence | None
    if confidence_text == FROM_SERVICE:
        if service is None:
            raise RuleError(
                RuleErrorCode.INVALID_VALUE,
                f"{location}.confidence",
                "from_service needs a service condition in when",
            )
        confidence = None
    else:
        confidence = _choice(confidence_text, f"{location}.confidence", Confidence)

    return FindingRule(
        id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        references=references,
        service=service,
        tls_versions=versions,
        tls_expired="tls_expired" in when,
        tls_hostname_mismatch="tls_hostname_mismatch" in when,
        tls_self_issued="tls_self_issued" in when,
        tls_unreadable="tls_unreadable" in when,
    )


def parse_finding_rules(text: str) -> FindingRuleSet:
    """Validate one finding rule document and return its rules, in file order."""
    return FindingRuleSet(tuple(parse_rule_document(text, _rule)))


def evidence_fields_markdown() -> str:
    """The evidence fields as the list docs/rules.md must contain."""
    return ", ".join(f"`{{{name}}}`" for name in sorted(EVIDENCE_FIELDS))


def markdown_table(rules: FindingRuleSet) -> str:
    """The rules as the Markdown table docs/rules.md must contain."""
    lines = [
        "| Rule | Severity | Confidence | References | Fires when |",
        "|------|----------|------------|------------|------------|",
    ]
    for rule in rules.rules:
        confidence = "from the service" if rule.confidence is None else rule.confidence.value
        references = ", ".join(rule.references) or "none"
        lines.append(
            f"| `{rule.id}` | {rule.severity.value} | {confidence} | {references} | {rule.title} |"
        )
    return "\n".join(lines)
