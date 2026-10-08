"""Default limits and hard ceilings (PLAN.md section 4.6).

Ceilings are module constants. A `Limits` value can be lowered or raised up to its
ceiling, never past it, and every field must be positive.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from network_scanner.core.errors import LimitError


@dataclass(frozen=True, slots=True)
class Limits:
    """Per-run limits. Defaults match PLAN.md section 4.6."""

    max_targets: int = 256
    max_ports_per_target: int = 1024
    concurrency: int = 64
    connections_per_second: int = 100
    connect_timeout_s: float = 3.0
    banner_timeout_s: float = 2.0
    banner_max_bytes: int = 1024
    total_timeout_s: float = 300.0
    probes_per_open_port: int = 3

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            ceiling = CEILINGS[field.name]
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise LimitError(f"{field.name} must be a number")
            if not 0 < value <= ceiling:
                raise LimitError(f"{field.name} must be greater than 0 and at most {ceiling}")


CEILINGS: dict[str, int | float] = {
    "max_targets": 4096,
    "max_ports_per_target": 65535,
    "concurrency": 512,
    "connections_per_second": 1000,
    "connect_timeout_s": 30.0,
    "banner_timeout_s": 10.0,
    "banner_max_bytes": 4096,
    "total_timeout_s": 3600.0,
    "probes_per_open_port": 3,
}

DEFAULT_LIMITS = Limits()

# Fixed input bounds. They are not per-run settings, so they are not part of `Limits`.
MAX_TARGET_CHARS = 255  # one target string (PLAN.md section 4.1)
MAX_DNS_ANSWERS = 8  # a name with more answers is refused (PLAN.md section 4.4)
RESOLVE_TIMEOUT_S = 5.0  # handed to the injected resolver for the single lookup
MAX_SCOPE_FILE_BYTES = 64 * 1024  # PLAN.md section 4.3
MAX_SCOPE_ENTRIES = 4096
MAX_PORT_SPEC_CHARS = 4096
MAX_PROBES_PER_RUN = 100_000  # targets x ports, so results and work stay bounded

# Reading what a service sends back (Phase 4). Everything a remote service sends is hostile,
# so every read has a byte cap, a line cap where lines exist, and a deadline. The banner
# deadline is `Limits.banner_timeout_s` and its byte cap is `Limits.banner_max_bytes`.
MAX_BANNER_CHARS = 256  # sanitised banner text kept per port
HTTP_HEAD_TIMEOUT_S = 5.0  # request sent and response head read, all within this deadline
MAX_HTTP_HEAD_BYTES = 4096  # status line and headers; the body is never read
MAX_HTTP_HEADER_LINES = 64  # header lines looked at; the rest are ignored
MAX_HTTP_SERVER_CHARS = 200  # sanitised Server header kept
TLS_HANDSHAKE_TIMEOUT_S = 5.0  # handshake deadline, after the connection is established
CLOSE_TIMEOUT_S = 1.0  # a polite close waits this long, then the connection is aborted
ABORT_GRACE_S = 0.1  # after an abort, how long to wait for the transport to report closed
MAX_CERT_DER_BYTES = 32 * 1024  # a larger certificate is not parsed at all
MAX_CERT_FIELD_CHARS = 256  # sanitised subject, issuer and each subjectAltName entry kept
MAX_SAN_ENTRIES = 64  # subjectAltName entries kept

# Rule files and the regular expressions in them (Phase 4, PLAN.md risk R4).
MAX_RULE_FILE_BYTES = 64 * 1024
MAX_RULES = 256  # rules per file
MAX_RULE_FILES = 32  # files accepted by one `rules validate` call
MAX_REGEX_PATTERN_CHARS = 200
MAX_REGEX_INPUT_CHARS = 256  # a pattern is only ever run on this many leading characters
MAX_REGEX_REPEAT = 255  # largest count in {m,n}
MAX_REGEX_COST = 100_000  # budget for the backtracking estimate (see rules/regex_safety.py)
MAX_REGEX_GROUP_DEPTH = 6

# Findings (Phase 5).
MAX_EVIDENCE_CHARS = 400  # sanitised evidence text kept per finding

# Baselines (Phase 5).
MAX_BASELINE_BYTES = 16 * 1024 * 1024  # a larger baseline file is refused unread
MAX_BASELINE_ENTRIES = 100_000  # as many as MAX_PROBES_PER_RUN, the most one scan can probe
