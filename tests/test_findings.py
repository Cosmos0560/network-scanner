"""Finding rules: the schema, and the evaluator against every built-in rule."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from network_scanner.core.limits import MAX_EVIDENCE_CHARS, MAX_RULE_FILE_BYTES, MAX_RULES
from network_scanner.core.model import (
    Confidence,
    Observation,
    PortObservation,
    Service,
    Severity,
    TlsInfo,
)
from network_scanner.findings.evaluate import evaluate_findings, rule_applies
from network_scanner.fingerprint.match import attach_services
from network_scanner.rules.findings_schema import (
    EVIDENCE_FIELDS,
    FindingRule,
    parse_finding_rules,
)
from network_scanner.rules.loader import (
    builtin_finding_rules,
    builtin_fingerprint_rules,
    load_finding_rules,
)
from network_scanner.rules.schema import RuleError, RuleErrorCode

BUILTIN = builtin_finding_rules()


def tls(**changes: object) -> TlsInfo:
    base = TlsInfo(
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        subject="CN=lab.test",
        issuer="CN=Lab CA",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        san=("DNS:lab.test",),
        san_truncated=False,
        sha256="ab" * 32,
        self_issued=False,
        self_signature_valid=False,
        expired=False,
        hostname_match=True,
        parse_error=None,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def port(
    *,
    banner: str | None = None,
    http_server: str | None = None,
    service: Service | None = None,
    tls_info: TlsInfo | None = None,
    number: int = 8000,
) -> PortObservation:
    seen = Observation(banner, False, None, None, http_server, tls_info)
    return PortObservation("10.0.0.5", number, seen, service)


TELNET_LOW = Service("telnet", "telnet-login-prompt", Confidence.LOW)
FTP_MEDIUM = Service("ftp", "ftp-greeting", Confidence.MEDIUM)
SSH_HIGH = Service("ssh", "ssh-identification", Confidence.HIGH)

# rule id -> (a port the rule must fire on, a port it must not fire on)
CASES: dict[str, tuple[PortObservation, PortObservation]] = {
    "cleartext-telnet": (
        port(banner="login:", service=TELNET_LOW),
        port(banner="SSH-2.0-x", service=SSH_HIGH),
    ),
    "cleartext-ftp": (
        port(banner="220 FTP ready", service=FTP_MEDIUM),
        port(banner="220 SMTP ready", service=Service("smtp", "smtp-greeting", Confidence.MEDIUM)),
    ),
    "tls-deprecated-version": (
        port(tls_info=tls(version="TLSv1")),
        port(tls_info=tls(version="TLSv1.2")),
    ),
    "tls-certificate-expired": (
        port(tls_info=tls(expired=True)),
        port(tls_info=tls(expired=False)),
    ),
    "tls-certificate-hostname-mismatch": (
        port(tls_info=tls(hostname_match=False)),
        port(tls_info=tls(hostname_match=None)),  # unknown is not a mismatch
    ),
    "tls-certificate-self-issued": (
        port(tls_info=tls(self_issued=True, self_signature_valid=True)),
        port(tls_info=tls(self_issued=False)),
    ),
    "tls-certificate-unreadable": (
        port(tls_info=tls(parse_error="malformed_certificate")),
        port(tls_info=tls(parse_error=None)),
    ),
}


def fired(found: PortObservation) -> list[str]:
    return [finding.id for finding in evaluate_findings([found], BUILTIN)]


def test_every_built_in_rule_has_a_positive_and_a_negative_case() -> None:
    assert sorted(CASES) == sorted(rule.id for rule in BUILTIN.rules)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_rule_fires_on_its_positive_case_and_not_on_its_negative_case(rule_id: str) -> None:
    positive, negative = CASES[rule_id]
    assert rule_id in fired(positive)
    assert rule_id not in fired(negative)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_every_finding_carries_evidence_and_keeps_severity_and_confidence_apart(
    rule_id: str,
) -> None:
    positive, _ = CASES[rule_id]
    [finding] = [f for f in evaluate_findings([positive], BUILTIN) if f.id == rule_id]
    rule = next(r for r in BUILTIN.rules if r.id == rule_id)
    assert finding.evidence.startswith("10.0.0.5:8000 ")
    assert "{" not in finding.evidence
    assert len(finding.evidence) <= MAX_EVIDENCE_CHARS
    assert (finding.address, finding.port, finding.title) == ("10.0.0.5", 8000, rule.title)
    assert isinstance(finding.severity, Severity)
    assert isinstance(finding.confidence, Confidence)
    assert finding.references == rule.references


def test_exact_evidence_for_the_certificate_rules() -> None:
    expired = port(tls_info=tls(expired=True))
    [finding] = [
        f for f in evaluate_findings([expired], BUILTIN) if f.id == "tls-certificate-expired"
    ]
    assert finding.evidence == (
        "10.0.0.5:8000 presented a certificate valid from 2026-01-01T00:00:00+00:00 to "
        f"2027-01-01T00:00:00+00:00 (subject CN=lab.test, sha256 {'ab' * 32}); "
        "the scan ran after notAfter"
    )
    assert (finding.severity, finding.confidence) == (Severity.MEDIUM, Confidence.HIGH)
    assert finding.references == ("RFC 5280 section 4.1.2.5",)
    mismatch = port(tls_info=tls(hostname_match=False))
    [finding] = [
        f
        for f in evaluate_findings([mismatch], BUILTIN)
        if f.id == "tls-certificate-hostname-mismatch"
    ]
    assert finding.evidence == (
        "10.0.0.5:8000 presented a certificate for DNS:lab.test (subject CN=lab.test); "
        "the requested name is not among them"
    )
    issued = port(tls_info=tls(self_issued=True, self_signature_valid=None))
    [finding] = [
        f for f in evaluate_findings([issued], BUILTIN) if f.id == "tls-certificate-self-issued"
    ]
    assert finding.evidence == (
        "10.0.0.5:8000 subject CN=lab.test, issuer CN=Lab CA; "
        "signature verifies under its own key: unknown"
    )
    assert finding.severity is Severity.INFO


def test_a_synthetic_old_tls_version_is_a_finding_for_each_deprecated_version() -> None:
    for version in ("SSLv3", "TLSv1", "TLSv1.1"):
        [finding] = evaluate_findings([port(tls_info=tls(version=version))], BUILTIN)
        assert finding.id == "tls-deprecated-version"
        assert f"negotiated {version} (cipher TLS_AES_256_GCM_SHA384)" in finding.evidence
        assert finding.references == ("RFC 8996",)
    assert evaluate_findings([port(tls_info=tls(version="TLSv1.3"))], BUILTIN) == ()


def test_a_service_finding_takes_its_confidence_from_the_fingerprint_and_not_its_severity() -> None:
    [low] = evaluate_findings([CASES["cleartext-telnet"][0]], BUILTIN)
    assert (low.severity, low.confidence) == (Severity.MEDIUM, Confidence.LOW)
    high_telnet = port(banner="login:", service=Service("telnet", "x", Confidence.HIGH))
    [high] = evaluate_findings([high_telnet], BUILTIN)
    assert (high.severity, high.confidence) == (Severity.MEDIUM, Confidence.HIGH)
    assert "fingerprint rule telnet-login-prompt, confidence low" in low.evidence
    assert low.references == ("CWE-319", "RFC 854")


def test_findings_come_out_port_by_port_and_rule_by_rule() -> None:
    both = port(tls_info=tls(expired=True, self_issued=True), number=1)
    other = port(banner="login:", service=TELNET_LOW, number=2)
    ids = [(f.port, f.id) for f in evaluate_findings([both, other], BUILTIN)]
    assert ids == [
        (1, "tls-certificate-expired"),
        (1, "tls-certificate-self-issued"),
        (2, "cleartext-telnet"),
    ]


def test_nothing_inspected_gives_no_findings() -> None:
    assert evaluate_findings([], BUILTIN) == ()
    assert evaluate_findings([port()], BUILTIN) == ()


def test_evidence_is_sanitised_again_and_capped() -> None:
    nasty = port(banner="\x1b[31mlogin:\x07\u202e" + "x" * 900, service=TELNET_LOW)
    [finding] = evaluate_findings([nasty], BUILTIN)
    for forbidden in ("\x1b", "\x07", "\u202e"):
        assert forbidden not in finding.evidence
    assert len(finding.evidence) == MAX_EVIDENCE_CHARS
    assert finding.evidence.endswith("...")


def test_missing_facts_are_shown_as_none_or_unknown() -> None:
    bare = port(service=TELNET_LOW)
    [finding] = evaluate_findings([bare], BUILTIN)
    assert finding.evidence.endswith("Banner: none")


def test_the_san_list_shows_that_it_was_cut() -> None:
    cut = port(
        tls_info=tls(hostname_match=False, san=("DNS:a.test", "DNS:b.test"), san_truncated=True)
    )
    [finding] = [f for f in evaluate_findings([cut], BUILTIN) if "hostname" in f.id]
    assert "DNS:a.test, DNS:b.test, ..." in finding.evidence


def test_services_are_attached_to_inspected_ports_by_the_fingerprint_rules() -> None:
    rules = builtin_fingerprint_rules()
    ssh = port(banner="SSH-2.0-OpenSSH_9.6")
    unknown = port(banner="hello")
    attached = attach_services([ssh, unknown], rules)
    assert attached[0].service == Service("ssh", "ssh-identification", Confidence.HIGH)
    assert attached[1].service is None
    assert attached[0].observation == ssh.observation


def test_rule_applies_requires_every_condition() -> None:
    rule = next(r for r in BUILTIN.rules if r.id == "cleartext-telnet")
    assert rule_applies(rule, port(service=TELNET_LOW))
    assert not rule_applies(rule, port(service=None))


# -- the schema ------------------------------------------------------------------------------

VALID = """\
schema_version: 1
rules:
  - id: demo
    title: A demo finding
    severity: low
    confidence: from_service
    description: A description.
    references: [CWE-319, RFC 5280 section 4.1.2.5]
    evidence: "{address}:{port} is {service}"
    when:
      service: telnet
      tls_version_in: [TLSv1]
      tls_expired: true
"""


WHEN_BLOCK = (
    "    when:\n      service: telnet\n      tls_version_in: [TLSv1]\n      tls_expired: true\n"
)


def error_of(text: str) -> RuleError:
    with pytest.raises(RuleError) as caught:
        parse_finding_rules(text)
    return caught.value


def changed(old: str, new: str) -> str:
    assert old in VALID
    return VALID.replace(old, new)


def test_a_valid_finding_rule_parses_completely() -> None:
    [rule] = parse_finding_rules(VALID).rules
    assert rule == FindingRule(
        id="demo",
        title="A demo finding",
        severity=Severity.LOW,
        confidence=None,
        description="A description.",
        evidence="{address}:{port} is {service}",
        references=("CWE-319", "RFC 5280 section 4.1.2.5"),
        service="telnet",
        tls_versions=("TLSv1",),
        tls_expired=True,
        tls_hostname_mismatch=False,
        tls_self_issued=False,
        tls_unreadable=False,
    )


def test_references_are_optional() -> None:
    text = changed("    references: [CWE-319, RFC 5280 section 4.1.2.5]\n", "")
    assert parse_finding_rules(text).rules[0].references == ()


CASES_BAD = [
    (VALID + "extra: 1\n", "unknown_key", "extra"),
    (
        changed("    title: A demo finding\n", "    title: A demo finding\n    colour: red\n"),
        "unknown_key",
        "rules[0].colour",
    ),
    (
        changed("      tls_expired: true\n", "      tls_expired: true\n      port: 80\n"),
        "unknown_key",
        "rules[0].when.port",
    ),
    (changed("    title: A demo finding\n", ""), "missing_key", "rules[0]"),
    (changed('    evidence: "{address}:{port} is {service}"\n', ""), "missing_key", "rules[0]"),
    (changed("    severity: low\n", ""), "missing_key", "rules[0]"),
    (
        changed(
            WHEN_BLOCK,
            "",
        ),
        "missing_key",
        "rules[0]",
    ),
    (changed("severity: low", "severity: urgent"), "invalid_value", "rules[0].severity"),
    (changed("severity: low", "severity: 3"), "wrong_type", "rules[0].severity"),
    (
        changed("confidence: from_service", "confidence: certain"),
        "invalid_value",
        "rules[0].confidence",
    ),
    (
        changed(
            "      service: telnet\n      tls_version_in: [TLSv1]\n",
            "      tls_version_in: [TLSv1]\n",
        ),
        "invalid_value",
        "rules[0].confidence",
    ),
    (changed("id: demo", "id: Demo"), "invalid_value", "rules[0].id"),
    (changed("title: A demo finding", "title: ''"), "invalid_value", "rules[0].title"),
    (
        changed('evidence: "{address}:{port} is {service}"', 'evidence: "{password}"'),
        "invalid_value",
        "rules[0].evidence",
    ),
    (
        changed('evidence: "{address}:{port} is {service}"', 'evidence: "{address.__class__}"'),
        "invalid_value",
        "rules[0].evidence",
    ),
    (
        changed('evidence: "{address}:{port} is {service}"', 'evidence: "{{address}}"'),
        "invalid_value",
        "rules[0].evidence",
    ),
    (
        changed('evidence: "{address}:{port} is {service}"', 'evidence: "open {"'),
        "invalid_value",
        "rules[0].evidence",
    ),
    (
        changed('evidence: "{address}:{port} is {service}"', 'evidence: "' + "x" * 401 + '"'),
        "invalid_value",
        "rules[0].evidence",
    ),
    (
        changed("[CWE-319, RFC 5280 section 4.1.2.5]", "[CVE-2024-1234]"),
        "invalid_value",
        "rules[0].references[0]",
    ),
    (
        changed("[CWE-319, RFC 5280 section 4.1.2.5]", "[T1021.001]"),
        "invalid_value",
        "rules[0].references[0]",
    ),
    (
        changed("[CWE-319, RFC 5280 section 4.1.2.5]", "[CWE-319, CWE-1, CWE-2, CWE-3, CWE-4]"),
        "invalid_value",
        "rules[0].references",
    ),
    (
        changed("[CWE-319, RFC 5280 section 4.1.2.5]", "CWE-319"),
        "wrong_type",
        "rules[0].references",
    ),
    (changed("[CWE-319, RFC 5280 section 4.1.2.5]", "[5]"), "wrong_type", "rules[0].references[0]"),
    (
        changed("tls_version_in: [TLSv1]", "tls_version_in: []"),
        "invalid_value",
        "rules[0].when.tls_version_in",
    ),
    (
        changed("tls_version_in: [TLSv1]", "tls_version_in: TLSv1"),
        "wrong_type",
        "rules[0].when.tls_version_in",
    ),
    (
        changed("tls_version_in: [TLSv1]", "tls_version_in: ['TLS v1']"),
        "invalid_value",
        "rules[0].when.tls_version_in[0]",
    ),
    (
        changed("tls_expired: true", "tls_expired: false"),
        "invalid_value",
        "rules[0].when.tls_expired",
    ),
    (changed("tls_expired: true", "tls_expired: 1"), "wrong_type", "rules[0].when.tls_expired"),
    (changed("service: telnet", "service: TELNET"), "invalid_value", "rules[0].when.service"),
    (
        changed(
            WHEN_BLOCK,
            "    when: {}\n",
        ),
        "empty_match",
        "rules[0].when",
    ),
    (
        changed(
            WHEN_BLOCK,
            "    when: [x]\n",
        ),
        "wrong_type",
        "rules[0].when",
    ),
    (VALID + VALID.split("rules:\n")[1], "duplicate_id", "rules[1].id"),
    ("schema_version: 2\nrules: []\n", "unsupported_version", "schema_version"),
    ("schema_version: 1\nrules: []\n", "invalid_value", "rules"),
    ("rules: []\n", "missing_key", "<file>"),
    ("a: &x 1\nb: *x\n", "invalid_yaml", "<file>"),
    ("a: !!python/object/apply:os.system ['x']\n", "invalid_yaml", "<file>"),
]


@pytest.mark.parametrize(
    ("text", "code", "location"),
    CASES_BAD,
    ids=[f"{n}-{case[2]}-{case[1]}" for n, case in enumerate(CASES_BAD)],
)
def test_invalid_finding_rule_files_are_refused_with_a_specific_error(
    text: str, code: str, location: str
) -> None:
    error = error_of(text)
    assert (error.code.value, error.location) == (code, location)


def test_an_unknown_evidence_field_is_named() -> None:
    assert "{password}" in error_of(changed("{address}:{port} is {service}", "{password}")).detail


def test_every_allowed_evidence_field_is_accepted() -> None:
    template = " ".join("{" + name + "}" for name in sorted(EVIDENCE_FIELDS))
    text = changed("{address}:{port} is {service}", template)
    assert parse_finding_rules(text).rules[0].evidence == template


def test_the_rule_count_and_file_size_are_capped() -> None:
    body = "".join(
        f"  - id: r{n}\n    title: t\n    severity: low\n    confidence: low\n"
        "    description: d\n    evidence: e\n    when: {tls_expired: true}\n"
        for n in range(MAX_RULES + 1)
    )
    assert error_of("schema_version: 1\nrules:\n" + body).code is RuleErrorCode.TOO_MANY_RULES
    assert (
        error_of("# " + "x" * MAX_RULE_FILE_BYTES + "\n" + VALID).code
        is RuleErrorCode.FILE_TOO_LARGE
    )


def test_a_finding_rule_file_loads_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "findings.yaml"
    path.write_text(VALID, encoding="utf-8")
    assert [rule.id for rule in load_finding_rules(path).rules] == ["demo"]


def test_the_built_in_references_are_cwe_ids_and_rfc_numbers_only() -> None:
    allowed = ("CWE-", "RFC ")
    for rule in BUILTIN.rules:
        assert all(ref.startswith(allowed) for ref in rule.references), rule.id
        assert "ATT" not in "".join(rule.references)


def test_the_built_in_rules_have_unique_ids_and_a_non_empty_title_and_evidence() -> None:
    ids = [rule.id for rule in BUILTIN.rules]
    assert len(ids) == len(set(ids))
    assert all(rule.title and rule.evidence and rule.description for rule in BUILTIN.rules)
