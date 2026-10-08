"""Fingerprint matching: the built-in rules against known observations, and the precedence."""

from __future__ import annotations

import pytest

from network_scanner.core.model import Confidence, Observation, Service, TlsInfo
from network_scanner.fingerprint.match import identify, rule_applies
from network_scanner.rules.loader import builtin_fingerprint_rules
from network_scanner.rules.schema import parse_fingerprint_rules


def observation(
    *,
    banner: str | None = None,
    http_status: int | None = None,
    http_server: str | None = None,
    tls_version: str | None = None,
    has_tls: bool = False,
) -> Observation:
    tls = None
    if has_tls or tls_version is not None:
        tls = TlsInfo(
            version=tls_version,
            cipher=None,
            subject=None,
            issuer=None,
            not_before=None,
            not_after=None,
            san=(),
            sha256=None,
            self_issued=None,
            self_signature_valid=None,
            expired=None,
            hostname_match=None,
            parse_error=None,
            san_truncated=False,
        )
    return Observation(
        banner=banner,
        banner_truncated=False,
        probe=None,
        http_status=http_status,
        http_server=http_server,
        tls=tls,
    )


BUILTIN = builtin_fingerprint_rules()

# (observation, expected service name, expected rule id, expected confidence)
POSITIVE = [
    (observation(banner="SSH-2.0-OpenSSH_9.6"), "ssh", "ssh-identification", Confidence.HIGH),
    (observation(banner="SSH-1.99-Cisco-1.25"), "ssh", "ssh-identification", Confidence.HIGH),
    (observation(banner="RFB 003.008"), "vnc", "vnc-protocol-version", Confidence.HIGH),
    (
        observation(http_status=200, http_server="nginx"),
        "http",
        "http-status-line",
        Confidence.HIGH,
    ),
    (observation(http_status=404), "http", "http-status-line", Confidence.HIGH),
    (observation(tls_version="TLSv1.3"), "tls", "tls-handshake", Confidence.HIGH),
    (observation(banner="220 ProFTPD Server ready"), "ftp", "ftp-greeting", Confidence.MEDIUM),
    (observation(banner="220-Welcome to FTP"), "ftp", "ftp-greeting", Confidence.MEDIUM),
    (
        observation(banner="220 mail.example ESMTP Postfix"),
        "smtp",
        "smtp-greeting",
        Confidence.MEDIUM,
    ),
    (observation(banner="+OK POP3 server ready"), "pop3", "pop3-greeting", Confidence.MEDIUM),
    (observation(banner="* OK IMAP4rev1 ready"), "imap", "imap-greeting", Confidence.MEDIUM),
    (
        observation(banner="Debian GNU/Linux\nlogin:"),
        "telnet",
        "telnet-login-prompt",
        Confidence.LOW,
    ),
    (observation(banner="Router Login:"), "telnet", "telnet-login-prompt", Confidence.LOW),
]


@pytest.mark.parametrize(
    ("seen", "name", "rule_id", "confidence"),
    POSITIVE,
    ids=[f"{n}-{case[1]}" for n, case in enumerate(POSITIVE)],
)
def test_the_built_in_rules_identify_known_observations(
    seen: Observation, name: str, rule_id: str, confidence: Confidence
) -> None:
    assert identify(seen, BUILTIN) == Service(name, rule_id, confidence)


NEGATIVE = [
    observation(),
    observation(banner=""),
    observation(banner="hello"),
    observation(banner="SSH-2.0"),  # no software version separator
    observation(banner="xSSH-2.0-OpenSSH"),  # not at the start
    observation(banner="RFB 3.8"),
    observation(banner="220 Welcome"),  # a 220 greeting that names neither FTP nor SMTP
    observation(banner="OK"),
    observation(banner="login: and then more"),  # a prompt must end the text
    observation(http_server="nginx"),  # a Server header without a status line
    observation(has_tls=True),  # a TLS record without a completed handshake (no version)
]


@pytest.mark.parametrize("seen", NEGATIVE, ids=range(len(NEGATIVE)))
def test_unrelated_observations_match_nothing(seen: Observation) -> None:
    assert identify(seen, BUILTIN) is None


RULES = """\
schema_version: 1
rules:
  - id: generic
    service: web
    confidence: low
    description: Anything that answers HTTP.
    match: {http_response: true}
  - id: nginx
    service: nginx
    confidence: high
    description: An HTTP answer from nginx.
    match: {http_response: true, http_server_regex: '^nginx'}
  - id: also-high
    service: web2
    confidence: high
    description: Same strength as nginx, later in the file.
    match: {http_response: true}
  - id: needs-both
    service: both
    confidence: high
    description: Needs a banner and TLS.
    match: {banner_regex: 'hello', tls: true}
"""


def test_the_highest_confidence_wins_and_a_tie_goes_to_the_earlier_rule() -> None:
    rules = parse_fingerprint_rules(RULES)
    plain = observation(http_status=200, http_server="Apache")
    assert identify(plain, rules) == Service("web2", "also-high", Confidence.HIGH)
    nginx = observation(http_status=200, http_server="nginx/1.25")
    assert identify(nginx, rules) == Service("nginx", "nginx", Confidence.HIGH)


def test_every_condition_of_a_rule_must_hold() -> None:
    rules = parse_fingerprint_rules(RULES)
    both = rules.rules[3]
    assert not rule_applies(both, observation(banner="hello"))
    assert not rule_applies(both, observation(tls_version="TLSv1.2"))
    assert not rule_applies(both, observation(banner="goodbye", tls_version="TLSv1.2"))
    assert rule_applies(both, observation(banner="oh hello", tls_version="TLSv1.2"))


def test_matching_does_not_depend_on_the_order_the_observation_was_built_in() -> None:
    rules = parse_fingerprint_rules(RULES)
    seen = observation(http_status=200, http_server="nginx", banner="hello")
    assert identify(seen, rules) == identify(seen, rules)


def test_a_banner_beyond_the_input_cap_is_not_searched() -> None:
    rules = parse_fingerprint_rules(RULES)
    far = observation(banner="x" * 300 + "hello", tls_version="TLSv1.3")
    assert not rule_applies(rules.rules[3], far)
