"""Exit codes and the error hierarchy shared by every layer."""

from __future__ import annotations

from enum import IntEnum, StrEnum


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


class ConnectError(NetworkScannerError):
    """A connection attempt failed; `code` is the normalised reason."""

    def __init__(self, code: NetErrorCode) -> None:
        super().__init__(code.value)
        self.code = code
