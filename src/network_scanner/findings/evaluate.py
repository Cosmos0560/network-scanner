"""Turn inspected ports into findings using validated finding rules.

Pure and deterministic. For each inspected port, in the order given, every rule whose
conditions all hold produces one finding, in the order of the rule file. Severity comes from
the rule; confidence comes from the rule or, for `from_service`, from the fingerprint rule that
named the service. The evidence is the rule's template filled with facts about the port, then
sanitised again and capped, so nothing a remote service sent can reach a report unclean.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from network_scanner.core.limits import MAX_EVIDENCE_CHARS
from network_scanner.core.model import Finding, PortObservation, TlsInfo
from network_scanner.core.sanitize import sanitize_text
from network_scanner.rules.findings_schema import FindingRule, FindingRuleSet

_PLACEHOLDER = re.compile(r"\{([a-z_0-9]+)\}")
_NONE = "none"


def _flag(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _facts(found: PortObservation) -> dict[str, str]:
    seen = found.observation
    tls: TlsInfo | None = seen.tls
    service = found.service
    facts = {
        "address": found.address,
        "port": str(found.port),
        "service": service.name if service else _NONE,
        "service_rule": service.rule_id if service else _NONE,
        "service_confidence": service.confidence.value if service else _NONE,
        "banner": seen.banner if seen.banner is not None else _NONE,
        "http_server": seen.http_server if seen.http_server is not None else _NONE,
    }
    facts.update(
        {
            "tls_version": (tls.version if tls else None) or _NONE,
            "tls_cipher": (tls.cipher if tls else None) or _NONE,
            "tls_subject": (tls.subject if tls else None) or _NONE,
            "tls_issuer": (tls.issuer if tls else None) or _NONE,
            "tls_not_before": (tls.not_before if tls else None) or _NONE,
            "tls_not_after": (tls.not_after if tls else None) or _NONE,
            "tls_san": (", ".join(tls.san) + (", ..." if tls.san_truncated else "")) or _NONE
            if tls
            else _NONE,
            "tls_self_issued": _flag(tls.self_issued if tls else None),
            "tls_self_signature_valid": _flag(tls.self_signature_valid if tls else None),
            "tls_expired": _flag(tls.expired if tls else None),
            "tls_hostname_match": _flag(tls.hostname_match if tls else None),
            "tls_sha256": (tls.sha256 if tls else None) or _NONE,
            "tls_parse_error": (tls.parse_error if tls else None) or _NONE,
        }
    )
    return facts


def rule_applies(rule: FindingRule, found: PortObservation) -> bool:
    """True if every condition of `rule` holds for the inspected port."""
    tls = found.observation.tls
    if rule.service is not None and (found.service is None or found.service.name != rule.service):
        return False
    if rule.tls_versions and (tls is None or tls.version not in rule.tls_versions):
        return False
    if rule.tls_expired and (tls is None or tls.expired is not True):
        return False
    if rule.tls_hostname_mismatch and (tls is None or tls.hostname_match is not False):
        return False
    if rule.tls_self_issued and (tls is None or tls.self_issued is not True):
        return False
    return not (rule.tls_unreadable and (tls is None or tls.parse_error is None))


def _finding(rule: FindingRule, found: PortObservation) -> Finding:
    facts = _facts(found)
    evidence = _PLACEHOLDER.sub(lambda match: facts[match.group(1)], rule.evidence)
    if rule.confidence is not None:
        confidence = rule.confidence
    else:
        # from_service: the schema guarantees a service condition, so the service exists here.
        assert found.service is not None  # noqa: S101  (an invariant of rule_applies)
        confidence = found.service.confidence
    return Finding(
        id=rule.id,
        title=rule.title,
        severity=rule.severity,
        confidence=confidence,
        address=found.address,
        port=found.port,
        evidence=sanitize_text(evidence, max_chars=MAX_EVIDENCE_CHARS).text,
        references=rule.references,
    )


def evaluate_findings(
    inspected: Iterable[PortObservation], rules: FindingRuleSet
) -> tuple[Finding, ...]:
    """The findings for `inspected`, port by port, rule by rule."""
    return tuple(
        _finding(rule, found)
        for found in inspected
        for rule in rules.rules
        if rule_applies(rule, found)
    )
