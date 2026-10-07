"""Normalise OS-level connection errors into our own `NetErrorCode` enum.

Windows and Linux report the same situations differently: a refused connection is
`ConnectionRefusedError` on both, but the underlying number is WSAECONNREFUSED (10061) or
ERROR_CONNECTION_REFUSED (1225) on Windows and ECONNREFUSED elsewhere, and the asyncio
Proactor loop surfaces some failures as plain `OSError` with only a `winerror`. The
mapping is table-driven and tested with synthetic exceptions, so it runs on every platform.
"""

from __future__ import annotations

import errno

from network_scanner.core.errors import NetErrorCode


def _errnos(*names: str) -> frozenset[int]:
    return frozenset(
        value for name in names if isinstance(value := getattr(errno, name, None), int)
    )


_ERRNO_REFUSED = _errnos("ECONNREFUSED")
_ERRNO_TIMEOUT = _errnos("ETIMEDOUT")
_ERRNO_RESET = _errnos("ECONNRESET", "ECONNABORTED", "EPIPE")
_ERRNO_UNREACHABLE = _errnos("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EHOSTDOWN")

# Windows error numbers: WSA codes (10xxx) and system codes (1xxx, 121).
_WINERROR_REFUSED = frozenset({10061, 1225})  # WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
_WINERROR_TIMEOUT = frozenset({10060, 121})  # WSAETIMEDOUT, ERROR_SEM_TIMEOUT
_WINERROR_RESET = frozenset({10054, 10053, 1236})  # WSAECONNRESET, WSAECONNABORTED, aborted
_WINERROR_UNREACHABLE = frozenset({10050, 10051, 10064, 10065, 1231, 1232})


def normalise(exc: BaseException) -> NetErrorCode:
    """Map an exception raised while connecting onto a `NetErrorCode`."""
    if isinstance(exc, TimeoutError):
        return NetErrorCode.TIMEOUT
    if isinstance(exc, ConnectionRefusedError):
        return NetErrorCode.REFUSED
    if isinstance(exc, ConnectionResetError | ConnectionAbortedError | BrokenPipeError):
        return NetErrorCode.RESET
    if not isinstance(exc, OSError):
        return NetErrorCode.OTHER
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        for codes, result in (
            (_WINERROR_REFUSED, NetErrorCode.REFUSED),
            (_WINERROR_TIMEOUT, NetErrorCode.TIMEOUT),
            (_WINERROR_RESET, NetErrorCode.RESET),
            (_WINERROR_UNREACHABLE, NetErrorCode.UNREACHABLE),
        ):
            if winerror in codes:
                return result
    number = exc.errno
    if isinstance(number, int):
        for codes, result in (
            (_ERRNO_REFUSED, NetErrorCode.REFUSED),
            (_ERRNO_TIMEOUT, NetErrorCode.TIMEOUT),
            (_ERRNO_RESET, NetErrorCode.RESET),
            (_ERRNO_UNREACHABLE, NetErrorCode.UNREACHABLE),
        ):
            if number in codes:
                return result
    return NetErrorCode.OTHER
