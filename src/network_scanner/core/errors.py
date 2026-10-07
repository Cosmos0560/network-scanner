"""Exit codes and the error hierarchy shared by every layer."""

from __future__ import annotations

from enum import IntEnum, StrEnum

from network_scanner.core.sanitize import sanitize_text


class ReasonCode(StrEnum):
    """Stable scope-refusal reason codes (PLAN.md section 4.5, extended in Phase 2).

    The first six are named in the plan; the rest are the specific grammar and policy
    refusals Phase 2 needs. docs/scope-policy.md documents every code and a test keeps the
    document and this enum in step.
    """

    AMBIGUOUS_NUMERIC = "ambiguous_numeric"
    EMBEDDED_IPV4 = "embedded_ipv4"
    PUBLIC_NOT_ALLOWED = "public_not_allowed"
    NOT_IN_SCOPE_FILE = "not_in_scope_file"
    MIXED_DNS_ANSWERS = "mixed_dns_answers"
    TOO_MANY_TARGETS = "too_many_targets"
    INVALID_TARGET = "invalid_target"
    INVALID_CHARACTERS = "invalid_characters"
    TARGET_TOO_LONG = "target_too_long"
    INVALID_ZONE_ID = "invalid_zone_id"
    INVALID_CIDR = "invalid_cidr"
    CIDR_HOST_BITS = "cidr_host_bits"
    INVALID_RANGE = "invalid_range"
    INVALID_HOSTNAME = "invalid_hostname"
    ALWAYS_REFUSED = "always_refused"
    NO_TARGETS = "no_targets"
    DNS_FAILURE = "dns_failure"
    TOO_MANY_DNS_ANSWERS = "too_many_dns_answers"
    INVALID_DNS_ANSWER = "invalid_dns_answer"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_DECLINED = "confirmation_declined"


class NetErrorCode(StrEnum):
    """Our own normalised network error enum (OS-specific errors are mapped onto it)."""

    TIMEOUT = "timeout"
    REFUSED = "refused"
    RESET = "reset"
    UNREACHABLE = "unreachable"
    OTHER = "other"


class ExitCode(IntEnum):
    """Process exit codes (PLAN.md section 3)."""

    OK = 0
    FINDINGS = 1  # drift found, or findings at or above --fail-on
    USAGE = 2  # usage error or scope refusal
    RUNTIME = 3
    INTERRUPTED = 130  # partial report, complete: false


class NetworkScannerError(Exception):
    """Base class for every error raised on purpose by this project."""


class UsageError(NetworkScannerError):
    """The caller supplied an invalid value (maps to ExitCode.USAGE)."""


class LimitError(UsageError):
    """A configured limit is outside its allowed range."""


class ScopeRefusal(UsageError):
    """A target was refused (exit code 2). `target` is sanitised: it is untrusted input."""

    def __init__(self, reason_code: ReasonCode, target: str, detail: str) -> None:
        self.reason_code = reason_code
        self.target = sanitize_text(target, max_chars=80).text
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail} (target: {self.target!r})")


class ScopeFileError(UsageError):
    """The scope file is unreadable or invalid. `line` is 1-based when known."""

    def __init__(self, detail: str, *, line: int | None = None) -> None:
        self.detail = detail
        self.line = line
        super().__init__(detail if line is None else f"line {line}: {detail}")


class ResolutionError(NetworkScannerError):
    """A resolver could not answer for a name."""


class ConnectError(NetworkScannerError):
    """A connection attempt failed; `code` is the normalised reason."""

    def __init__(self, code: NetErrorCode) -> None:
        super().__init__(code.value)
        self.code = code
