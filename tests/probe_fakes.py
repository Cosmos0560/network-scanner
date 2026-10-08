"""Test doubles for probing: scripted streams, a connector that hands them out, a TLS prober.

Everything runs on the virtual-time loop, so a "slow" service costs no real time and the
elapsed virtual time can be asserted exactly. Nothing here touches a socket.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Mapping, Sequence

from network_scanner.core.errors import ConnectError, NetErrorCode
from network_scanner.core.interfaces import Connection
from network_scanner.core.model import TlsInfo

HANG = "hang"


class ScriptedStream:
    """A `Connection` whose reads follow a script.

    `chunks` is a list of (delay in seconds, bytes). A read waits for the next chunk's delay
    (or, if that is longer than the read's timeout, waits out the timeout and returns b""),
    then returns at most `max_bytes` of it and keeps the rest for the next read. When the
    script runs out the stream ends (b"") unless `endless` is set, which repeats that byte
    string forever, or `hang` is set, which makes every further read wait out its timeout.
    """

    def __init__(
        self,
        chunks: Sequence[tuple[float, bytes]] = (),
        *,
        endless: bytes | None = None,
        hang: bool = False,
        write_error: NetErrorCode | None = None,
        read_error: NetErrorCode | None = None,
    ) -> None:
        self._chunks = deque(chunks)
        self._endless = endless
        self._hang = hang
        self._write_error = write_error
        self._read_error = read_error
        self.written: list[bytes] = []
        self.requested: list[int] = []  # the max_bytes of every read
        self.delivered = 0  # bytes handed to the caller
        self.closed = 0

    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        self.requested.append(max_bytes)
        if self._read_error is not None:
            raise ConnectError(self._read_error)
        if not self._chunks:
            if self._endless is not None:
                data = (self._endless * (max_bytes // len(self._endless) + 1))[:max_bytes]
                self.delivered += len(data)
                return data
            if self._hang:
                await asyncio.sleep(timeout)
            return b""
        delay, data = self._chunks[0]
        if delay > timeout:
            await asyncio.sleep(timeout)
            return b""
        await asyncio.sleep(delay)
        self._chunks.popleft()
        if len(data) > max_bytes:
            self._chunks.appendleft((0.0, data[max_bytes:]))
            data = data[:max_bytes]
        self.delivered += len(data)
        return data

    async def write(self, data: bytes) -> None:
        if self._write_error is not None:
            raise ConnectError(self._write_error)
        self.written.append(data)

    async def close(self) -> None:
        self.closed += 1


class OverfullStream(ScriptedStream):
    """A misbehaving connection that returns more bytes than it was asked for."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = data

    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        self.requested.append(max_bytes)
        data, self._data = self._data, b""
        return data


Step = ScriptedStream | BaseException | str


class StreamConnector:
    """A `Connector` that hands out scripted streams, per port, in connection order.

    A step is a stream, an exception to raise, or HANG (the connect never finishes). A port
    with no steps left refuses the connection.
    """

    def __init__(self, plan: Mapping[int, Sequence[Step]]) -> None:
        self._plan = {port: deque(steps) for port, steps in plan.items()}
        self.connects: list[tuple[str, int]] = []
        self.streams: list[ScriptedStream] = []

    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        self.connects.append((address, port))
        steps = self._plan.get(port)
        if not steps:
            raise ConnectError(NetErrorCode.REFUSED)
        step = steps.popleft()
        if step == HANG:
            await asyncio.sleep(10**9)
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, ScriptedStream)
        self.streams.append(step)
        return step


class FakeTlsProber:
    """A `TlsProber` that returns, raises or hangs, and records how it was called."""

    def __init__(self, outcome: TlsInfo | BaseException | str) -> None:
        self._outcome = outcome
        self.calls: list[tuple[str, int, str | None, float]] = []

    async def handshake(
        self, address: str, port: int, *, server_name: str | None, timeout: float
    ) -> TlsInfo:
        self.calls.append((address, port, server_name, timeout))
        if self._outcome == HANG:
            await asyncio.sleep(10**9)
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        assert isinstance(self._outcome, TlsInfo)
        return self._outcome


class CountingLimiter:
    def __init__(self) -> None:
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


def tls_info(*, version: str | None = "TLSv1.3", parse_error: str | None = None) -> TlsInfo:
    return TlsInfo(
        version=version,
        cipher="TLS_AES_256_GCM_SHA384",
        subject="CN=lab.test",
        issuer="CN=lab.test",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        san=("DNS:lab.test",),
        san_truncated=False,
        sha256="ab" * 32,
        self_issued=True,
        self_signature_valid=True,
        expired=False,
        hostname_match=None,
        parse_error=parse_error,
    )
