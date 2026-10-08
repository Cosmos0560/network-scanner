"""Turn an observation into a service name using validated fingerprint rules.

Pure and deterministic. Every condition of a rule must hold. Among the rules that apply, the
one with the highest confidence wins and a tie goes to the earlier rule in the file, so the
answer never depends on anything but the observation and the rule file. Regular expressions
run through `search_bounded`, which looks only at the first `MAX_REGEX_INPUT_CHARS`
characters of the sanitised text.
"""

from __future__ import annotations

from network_scanner.core.model import Confidence, Observation, Service
from network_scanner.rules.regex_safety import search_bounded
from network_scanner.rules.schema import FingerprintRule, RuleSet

_CONFIDENCE_ORDER = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def rule_applies(rule: FingerprintRule, observation: Observation) -> bool:
    """True if every condition of `rule` holds for `observation`."""
    if rule.banner_pattern is not None and (
        observation.banner is None or not search_bounded(rule.banner_pattern, observation.banner)
    ):
        return False
    if rule.http_server_pattern is not None and (
        observation.http_server is None
        or not search_bounded(rule.http_server_pattern, observation.http_server)
    ):
        return False
    if rule.http_response and observation.http_status is None:
        return False
    return not (rule.tls and (observation.tls is None or observation.tls.version is None))


def identify(observation: Observation, rules: RuleSet) -> Service | None:
    """The best matching service for `observation`, or None if no rule applies."""
    best: FingerprintRule | None = None
    for rule in rules.rules:
        if not rule_applies(rule, observation):
            continue
        if best is None or _CONFIDENCE_ORDER.index(rule.confidence) > _CONFIDENCE_ORDER.index(
            best.confidence
        ):
            best = rule
    if best is None:
        return None
    return Service(name=best.service, rule_id=best.id, confidence=best.confidence)
