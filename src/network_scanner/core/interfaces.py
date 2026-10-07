"""Interfaces the engine depends on. Implementations live in `net`, `lab` and tests.

Decision logic never touches the wall clock, sleeping, DNS or sockets directly; it gets
one of these injected instead. Signatures are the Phase 1 contract and may be refined
when the adapters are built.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from network_scanner.core.model import TlsInfo


class Clock(Protocol):
    def monotonic(self) -> float:
        """Seconds from an arbitrary origin; only differences are meaningful."""

    def utc_now(self) -> datetime:
        """Timezone-aware current time in UTC."""


class Sleeper(Protocol):
    async def sleep(self, seconds: float) -> None:
        """Suspend for `seconds`."""


class Resolver(Protocol):
    async def resolve(self, name: str, *, timeout: float) -> tuple[str, ...]:
        """Return the address literals for `name` (at most the configured answer cap)."""


class Connection(Protocol):
    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        """Read at most `max_bytes`; b"" on timeout or end of stream."""

    async def write(self, data: bytes) -> None:
        """Send `data`."""

    async def close(self) -> None:
        """Close the connection. Safe to call more than once."""


class Connector(Protocol):
    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        """Open a TCP connection to the pinned IP literal `address`.

        Raises `ConnectError` carrying a normalised `NetErrorCode` on failure.
        """


class TlsProber(Protocol):
    async def handshake(
        self, address: str, port: int, *, server_name: str | None, timeout: float
    ) -> TlsInfo:
        """Perform a TLS handshake without verification and describe the certificate."""
