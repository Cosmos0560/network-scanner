"""Test doubles for the injected interfaces. Nothing here touches the network or real DNS."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from network_scanner.core.errors import (
    ConnectError,
    NetErrorCode,
    ReasonCode,
    ResolutionError,
    ScopeRefusal,
)
from network_scanner.core.interfaces import Connection


class FakeResolver:
    """A `Resolver` that answers from a dict and records every call.

    A value that is an exception instance (or class) is raised instead of returned;
    a name that is not in the dict raises `ResolutionError`, like an NXDOMAIN.
    """

    def __init__(
        self, answers: Mapping[str, tuple[str, ...] | BaseException] | None = None
    ) -> None:
        self.answers = dict(answers or {})
        self.calls: list[tuple[str, float]] = []

    async def resolve(self, name: str, *, timeout: float) -> tuple[str, ...]:
        self.calls.append((name, timeout))
        result = self.answers.get(name, ResolutionError(name))
        if isinstance(result, BaseException):
            raise result
        return result


# -- engine test doubles -------------------------------------------------------------------


class LoopClock:
    """A `Clock` that reads the running (virtual) event loop; wall time is fixed."""

    def monotonic(self) -> float:
        return asyncio.get_running_loop().time()

    def utc_now(self) -> datetime:
        return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class LoopSleeper:
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


@dataclass(frozen=True)
class Behaviour:
    """What a scripted connect does: wait `delay` seconds, then act out `kind`.

    kinds: open, refused, timeout, unreachable, reset, other (ConnectError with that code),
    hang (never finishes), oserror (a bare OSError), bug (an unexpected RuntimeError),
    policy (the connector's own scope check refuses).
    """

    kind: str = "open"
    delay: float = 0.0


class FakeConnection:
    def __init__(self, owner: ScriptedConnector) -> None:
        self._owner = owner

    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        return b""

    async def write(self, data: bytes) -> None:
        return None

    async def close(self) -> None:
        self._owner.closed += 1


_CODES = {
    "refused": NetErrorCode.REFUSED,
    "timeout": NetErrorCode.TIMEOUT,
    "unreachable": NetErrorCode.UNREACHABLE,
    "reset": NetErrorCode.RESET,
    "other": NetErrorCode.OTHER,
}


class ScriptedConnector:
    """A `Connector` driven by a function (address, port) -> Behaviour. Records everything."""

    def __init__(self, script: Callable[[str, int], Behaviour] | None = None) -> None:
        self.script = script or (lambda address, port: Behaviour())
        self.attempts: list[tuple[str, int, float]] = []  # address, port, virtual start time
        self.in_flight = 0
        self.max_in_flight = 0
        self.max_tasks = 0
        self.closed = 0
        self.opened = 0

    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        loop = asyncio.get_running_loop()
        self.attempts.append((address, port, loop.time()))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.max_tasks = max(self.max_tasks, len(asyncio.all_tasks(loop)))
        try:
            behaviour = self.script(address, port)
            if behaviour.kind == "hang":
                await asyncio.sleep(10**9)
            await asyncio.sleep(behaviour.delay)
            if behaviour.kind == "open":
                self.opened += 1
                return FakeConnection(self)
            if behaviour.kind == "oserror":
                raise OSError("synthetic")
            if behaviour.kind == "bug":
                raise RuntimeError("synthetic bug")
            if behaviour.kind == "policy":
                raise ScopeRefusal(ReasonCode.ALWAYS_REFUSED, address, "synthetic")
            raise ConnectError(_CODES[behaviour.kind])
        finally:
            self.in_flight -= 1


class NoLimit:
    """A `RateLimiter` that never waits, for tests that are not about rate."""

    async def acquire(self) -> None:
        return None
