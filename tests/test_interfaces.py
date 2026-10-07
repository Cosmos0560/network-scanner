"""The fakes below are assigned to Protocol-typed names, so mypy proves they conform."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from network_scanner.core.errors import ConnectError, NetErrorCode
from network_scanner.core.interfaces import (
    Clock,
    Connection,
    Connector,
    Resolver,
    Sleeper,
    TlsProber,
)
from network_scanner.core.model import TlsInfo

pytestmark = pytest.mark.leakcheck


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def utc_now(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)


class FakeSleeper:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.calls.append(seconds)
        self.clock.now += seconds


class FakeResolver:
    async def resolve(self, name: str, *, timeout: float) -> tuple[str, ...]:
        return ("127.0.0.1",) if name == "localhost" else ()


class FakeConnection:
    def __init__(self) -> None:
        self.sent = b""
        self.closed = 0

    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        return b"SSH-2.0-test"[:max_bytes]

    async def write(self, data: bytes) -> None:
        self.sent += data

    async def close(self) -> None:
        self.closed += 1


class FakeConnector:
    def __init__(self) -> None:
        self.connection = FakeConnection()

    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        if port != 22:
            raise ConnectError(NetErrorCode.REFUSED)
        return self.connection


class FakeTlsProber:
    async def handshake(
        self, address: str, port: int, *, server_name: str | None, timeout: float
    ) -> TlsInfo:
        return TlsInfo(
            version="TLSv1.3",
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
            parse_error="not parsed",
        )


def test_clock_and_sleeper_work_together() -> None:
    fake = FakeClock()
    clock: Clock = fake
    sleeper: Sleeper = FakeSleeper(fake)
    asyncio.run(sleeper.sleep(2.5))
    assert clock.monotonic() == 2.5
    assert clock.utc_now().tzinfo is not None


def test_resolver_contract() -> None:
    resolver: Resolver = FakeResolver()
    assert asyncio.run(resolver.resolve("localhost", timeout=1.0)) == ("127.0.0.1",)


def test_connector_and_connection_contract() -> None:
    async def scenario() -> tuple[bytes, int]:
        connector: Connector = FakeConnector()
        connection = await connector.connect("127.0.0.1", 22, timeout=1.0)
        banner = await connection.read(4, timeout=1.0)
        await connection.write(b"x")
        await connection.close()
        await connection.close()
        return banner, getattr(connection, "closed", -1)

    assert asyncio.run(scenario()) == (b"SSH-", 2)


def test_connector_failure_is_a_normalised_error() -> None:
    connector: Connector = FakeConnector()
    with pytest.raises(ConnectError) as caught:
        asyncio.run(connector.connect("127.0.0.1", 9, timeout=1.0))
    assert caught.value.code is NetErrorCode.REFUSED


def test_tls_prober_contract() -> None:
    prober: TlsProber = FakeTlsProber()
    info = asyncio.run(prober.handshake("127.0.0.1", 443, server_name=None, timeout=1.0))
    assert info.parse_error == "not parsed"
