from __future__ import annotations

import asyncio
import errno
import socket
from collections.abc import Callable
from typing import Any

import pytest

import hostile
from fakes import LoopClock, LoopSleeper, NoLimit
from network_scanner.core.errors import (
    ConnectError,
    NetErrorCode,
    ReasonCode,
    ResolutionError,
    ScopeRefusal,
)
from network_scanner.core.limits import Limits
from network_scanner.core.model import Family, PortState, ResolvedTarget, TargetKind, TargetSpec
from network_scanner.engine.scan import ScanStatus, run_scan
from network_scanner.lab.servers import LabError, PlainLab
from network_scanner.net.connector import AsyncioConnection, AsyncioConnector
from network_scanner.net.oserrors import normalise
from network_scanner.net.ratelimit import TokenBucket
from network_scanner.net.resolver import SystemResolver
from network_scanner.net.system import AsyncioSleeper, SystemClock
from network_scanner.scope.policy import ScopeOptions
from network_scanner.scope.scopefile import parse_scope_text
from virtual_loop import run_virtual

pytestmark = pytest.mark.leakcheck

# -- OS error normalisation ----------------------------------------------------------------


def with_winerror(number: int, base: type[OSError] = OSError) -> OSError:
    exc = base()
    setattr(exc, "winerror", number)  # noqa: B010  (a real attribute only on Windows)
    return exc


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (TimeoutError(), NetErrorCode.TIMEOUT),
        (ConnectionRefusedError(), NetErrorCode.REFUSED),
        (ConnectionResetError(), NetErrorCode.RESET),
        (ConnectionAbortedError(), NetErrorCode.RESET),
        (BrokenPipeError(), NetErrorCode.RESET),
        (OSError(errno.ECONNREFUSED, "refused"), NetErrorCode.REFUSED),
        (OSError(errno.ETIMEDOUT, "timed out"), NetErrorCode.TIMEOUT),
        (OSError(errno.ECONNRESET, "reset"), NetErrorCode.RESET),
        (OSError(errno.ECONNABORTED, "aborted"), NetErrorCode.RESET),
        (OSError(errno.ENETUNREACH, "net"), NetErrorCode.UNREACHABLE),
        (OSError(errno.EHOSTUNREACH, "host"), NetErrorCode.UNREACHABLE),
        (OSError(errno.ENETDOWN, "down"), NetErrorCode.UNREACHABLE),
        (OSError(errno.EACCES, "denied"), NetErrorCode.OTHER),
        (OSError("no number"), NetErrorCode.OTHER),
        (ValueError("not an os error"), NetErrorCode.OTHER),
        (RuntimeError(), NetErrorCode.OTHER),
    ],
)
def test_errors_are_normalised_by_class_and_errno(exc: BaseException, code: NetErrorCode) -> None:
    assert normalise(exc) is code


@pytest.mark.parametrize(
    ("winerror", "code"),
    [
        (10061, NetErrorCode.REFUSED),  # WSAECONNREFUSED
        (1225, NetErrorCode.REFUSED),  # ERROR_CONNECTION_REFUSED (what the Proactor loop shows)
        (10060, NetErrorCode.TIMEOUT),  # WSAETIMEDOUT
        (121, NetErrorCode.TIMEOUT),  # ERROR_SEM_TIMEOUT
        (10054, NetErrorCode.RESET),
        (10053, NetErrorCode.RESET),
        (1236, NetErrorCode.RESET),
        (10051, NetErrorCode.UNREACHABLE),
        (10065, NetErrorCode.UNREACHABLE),
        (1231, NetErrorCode.UNREACHABLE),
        (1232, NetErrorCode.UNREACHABLE),
        (5, NetErrorCode.OTHER),
    ],
)
def test_windows_error_numbers_are_normalised_on_every_platform(
    winerror: int, code: NetErrorCode
) -> None:
    assert normalise(with_winerror(winerror)) is code


def test_a_winerror_takes_precedence_over_a_misleading_errno() -> None:
    exc = with_winerror(1225)
    exc.errno = errno.EACCES
    assert normalise(exc) is NetErrorCode.REFUSED


# -- the token bucket ---------------------------------------------------------------------------


def test_the_bucket_spaces_sequential_acquires_exactly() -> None:
    async def main() -> list[float]:
        bucket = TokenBucket(rate=4, clock=LoopClock(), sleeper=LoopSleeper())
        loop = asyncio.get_running_loop()
        times = []
        for _ in range(5):
            await bucket.acquire()
            times.append(loop.time())
        return times

    assert run_virtual(main) == [0.0, 0.25, 0.5, 0.75, 1.0]


def test_many_waiting_tasks_get_distinct_wakeups_in_arrival_order() -> None:
    async def main() -> list[tuple[int, float]]:
        bucket = TokenBucket(rate=8, clock=LoopClock(), sleeper=LoopSleeper())
        loop = asyncio.get_running_loop()
        order: list[tuple[int, float]] = []

        async def user(number: int) -> None:
            await bucket.acquire()
            order.append((number, loop.time()))

        await asyncio.gather(*(user(n) for n in range(6)))
        return order

    assert run_virtual(main) == [(n, n * 0.125) for n in range(6)]


def test_an_idle_bucket_refills_but_never_beyond_its_capacity() -> None:
    async def main() -> list[float]:
        loop = asyncio.get_running_loop()
        bucket = TokenBucket(rate=4, clock=LoopClock(), sleeper=LoopSleeper())
        await asyncio.sleep(100)  # a long pause must not bank a burst
        times = []
        for _ in range(3):
            await bucket.acquire()
            times.append(loop.time() - 100)
        return times

    assert run_virtual(main) == [0.0, 0.25, 0.5]


def test_a_larger_capacity_allows_exactly_that_burst() -> None:
    async def main() -> list[float]:
        loop = asyncio.get_running_loop()
        bucket = TokenBucket(rate=2, capacity=3, clock=LoopClock(), sleeper=LoopSleeper())
        times = []
        for _ in range(5):
            await bucket.acquire()
            times.append(loop.time())
        return times

    assert run_virtual(main) == [0.0, 0.0, 0.0, 0.5, 1.0]


def test_a_cancelled_waiter_keeps_its_slot_so_the_limit_still_holds() -> None:
    async def main() -> float:
        loop = asyncio.get_running_loop()
        bucket = TokenBucket(rate=1, clock=LoopClock(), sleeper=LoopSleeper())
        await bucket.acquire()  # t=0, bucket now empty
        waiter = asyncio.create_task(bucket.acquire())  # reserves the slot at t=1
        await asyncio.sleep(0.5)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        await bucket.acquire()  # must not be earlier than t=2
        return loop.time()

    assert run_virtual(main) == 2.0


@pytest.mark.parametrize(
    ("rate", "capacity"), [(0, 1), (-1, 1), (float("nan"), 1), (1, 0.5), (1, float("nan"))]
)
def test_the_bucket_rejects_nonsense_settings(rate: float, capacity: float) -> None:
    async def main() -> None:
        TokenBucket(rate=rate, capacity=capacity, clock=LoopClock(), sleeper=LoopSleeper())

    with pytest.raises(ValueError, match="rate must be positive"):
        run_virtual(main)


# -- the real clock and sleeper ---------------------------------------------------------------


def test_the_system_clock_is_monotonic_and_timezone_aware() -> None:
    clock = SystemClock()
    first, second = clock.monotonic(), clock.monotonic()
    assert second >= first
    assert clock.utc_now().utcoffset() is not None


def test_the_asyncio_sleeper_sleeps_zero_without_error() -> None:
    asyncio.run(AsyncioSleeper().sleep(0))


# -- the system resolver (a fake lookup, so no DNS) ------------------------------------------------


def lookup_returning(rows: list[tuple[Any, ...]]) -> Callable[[str], Any]:
    async def lookup(name: str) -> list[tuple[Any, ...]]:
        return rows

    return lookup


def resolve(resolver: SystemResolver, timeout: float = 5.0) -> tuple[str, ...]:
    async def main() -> tuple[str, ...]:
        return await resolver.resolve("lab.example", timeout=timeout)

    return run_virtual(main)


def test_the_resolver_returns_unique_address_literals_in_order() -> None:
    rows: list[tuple[Any, ...]] = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 0, 0, 2)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
    ]
    assert resolve(SystemResolver(lookup_returning(rows))) == (
        "10.0.0.2",
        "fe80::1%eth0",
        "10.0.0.1",
    )


def test_the_resolver_ignores_rows_that_are_not_address_tuples() -> None:
    rows: list[tuple[Any, ...]] = [
        (1, 2, 3, "", "not a tuple"),
        (1, 2, 3, "", ()),
        (1, 2, 3, "", (5, 0)),
        (1, 2, 3, "", ("10.0.0.9", 0)),
    ]
    assert resolve(SystemResolver(lookup_returning(rows))) == ("10.0.0.9",)


def test_resolver_failures_become_resolution_errors() -> None:
    async def failing(name: str) -> list[tuple[Any, ...]]:
        raise socket.gaierror(socket.EAI_NONAME, "no such name")

    with pytest.raises(ResolutionError, match="failed"):
        resolve(SystemResolver(failing))


def test_a_lookup_that_never_answers_times_out_at_the_given_timeout() -> None:
    async def hanging(name: str) -> list[tuple[Any, ...]]:
        await asyncio.sleep(10**9)
        return []

    async def main() -> float:
        loop = asyncio.get_running_loop()
        with pytest.raises(ResolutionError, match="timed out"):
            await SystemResolver(hanging).resolve("lab.example", timeout=5.0)
        return loop.time()

    assert run_virtual(main) == 5.0


# -- the connector: the policy is re-checked before any socket exists ------------------------------


def forbid_sockets(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    async def fail(*args: Any, **kwargs: Any) -> None:
        calls.append(args)
        raise AssertionError("a socket was opened for an address the policy refuses")

    monkeypatch.setattr(asyncio, "open_connection", fail)
    return calls


def connect(connector: AsyncioConnector, address: str, port: int = 80, timeout: float = 5.0) -> Any:
    async def main() -> Any:
        return await connector.connect(address, port, timeout=timeout)

    return run_virtual(main)


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("169.254.169.254", ReasonCode.ALWAYS_REFUSED),
        ("0.0.0.0", ReasonCode.ALWAYS_REFUSED),
        ("224.0.0.1", ReasonCode.ALWAYS_REFUSED),
        ("255.255.255.255", ReasonCode.ALWAYS_REFUSED),
        ("192.0.2.1", ReasonCode.ALWAYS_REFUSED),
        ("::ffff:10.0.0.1", ReasonCode.EMBEDDED_IPV4),
        ("8.8.8.8", ReasonCode.PUBLIC_NOT_ALLOWED),
        ("100.64.0.1", ReasonCode.PUBLIC_NOT_ALLOWED),
        ("2606:4700::1", ReasonCode.PUBLIC_NOT_ALLOWED),
    ],
)
def test_the_connector_refuses_unapproved_addresses_before_opening_a_socket(
    monkeypatch: pytest.MonkeyPatch, address: str, reason: ReasonCode
) -> None:
    calls = forbid_sockets(monkeypatch)
    with pytest.raises(ScopeRefusal) as caught:
        connect(AsyncioConnector(ScopeOptions()), address)
    assert caught.value.reason_code is reason
    assert calls == []


@pytest.mark.parametrize(
    "address",
    [
        "localhost",
        "example.com",
        "127.1",
        "0x7f.0.0.1",
        "10.0.0.0/8",
        "10.0.0.1-5",
        "",
        "10.0.0.1 ",
    ],
)
def test_the_connector_accepts_only_plain_ip_literals(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    calls = forbid_sockets(monkeypatch)
    with pytest.raises(ScopeRefusal):
        connect(AsyncioConnector(ScopeOptions()), address)
    assert calls == []


@pytest.mark.parametrize("port", [0, -1, 65536, 10**9])
def test_the_connector_refuses_bad_ports(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    calls = forbid_sockets(monkeypatch)
    with pytest.raises(ValueError, match="port"):
        connect(AsyncioConnector(ScopeOptions()), "127.0.0.1", port)
    assert calls == []


def test_a_public_address_needs_the_flag_and_the_scope_file_at_the_connector_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = forbid_sockets(monkeypatch)
    only_flag = ScopeOptions(allow_public=True)
    only_file = ScopeOptions(scope_file=parse_scope_text("8.8.8.0/24\n"))
    for options, reason in (
        (only_flag, ReasonCode.NOT_IN_SCOPE_FILE),
        (only_file, ReasonCode.PUBLIC_NOT_ALLOWED),
    ):
        with pytest.raises(ScopeRefusal) as caught:
            connect(AsyncioConnector(options), "8.8.8.8")
        assert caught.value.reason_code is reason
    assert calls == []


def test_an_approved_public_address_reaches_the_socket_layer_numerically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def fake_open(*args: Any, **kwargs: Any) -> None:
        seen.append((args, kwargs))
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    options = ScopeOptions(allow_public=True, scope_file=parse_scope_text("8.8.8.0/24\n"))
    with pytest.raises(ConnectError) as caught:
        connect(AsyncioConnector(options), "8.8.8.8", 53)
    assert caught.value.code is NetErrorCode.REFUSED
    [(args, kwargs)] = seen
    assert args == ("8.8.8.8", 53)
    assert kwargs == {"family": socket.AF_INET, "flags": socket.AI_NUMERICHOST}  # never a lookup


def test_connect_errors_are_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    outcomes: list[BaseException] = [
        OSError(errno.ECONNRESET, "reset"),
        with_winerror(1225),
        OSError(errno.ENETUNREACH, "unreachable"),
        OSError("something else"),
    ]
    expected = [
        NetErrorCode.RESET,
        NetErrorCode.REFUSED,
        NetErrorCode.UNREACHABLE,
        NetErrorCode.OTHER,
    ]

    async def fake_open(*args: Any, **kwargs: Any) -> None:
        raise outcomes.pop(0)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    got = []
    for _ in expected:
        with pytest.raises(ConnectError) as caught:
            connect(AsyncioConnector(ScopeOptions()), "127.0.0.1")
        got.append(caught.value.code)
    assert got == expected


def test_a_connect_that_never_finishes_times_out_exactly_at_the_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def hang(*args: Any, **kwargs: Any) -> None:
        await asyncio.sleep(10**9)

    monkeypatch.setattr(asyncio, "open_connection", hang)

    async def main() -> float:
        loop = asyncio.get_running_loop()
        with pytest.raises(ConnectError) as caught:
            await AsyncioConnector(ScopeOptions()).connect("127.0.0.1", 80, timeout=3.0)
        assert caught.value.code is NetErrorCode.TIMEOUT
        return loop.time()

    assert run_virtual(main) == 3.0


# -- the connector against real loopback sockets ---------------------------------------------------


def test_connecting_to_an_open_port_and_talking_to_it() -> None:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(100)
        writer.write(data.upper())
        await writer.drain()
        writer.close()

    async def main() -> bytes:
        async with hostile.serve(echo) as server:
            connection = await AsyncioConnector(ScopeOptions()).connect(
                "127.0.0.1", server.port, timeout=10.0
            )
            await connection.write(b"hello")
            reply = await connection.read(100, timeout=10.0)
            await connection.close()
            await connection.close()  # closing twice is harmless
            await server.wait_handled(1)
            return reply

    assert asyncio.run(main()) == b"HELLO"


def test_a_bound_but_not_listening_port_is_refused() -> None:
    async def main() -> NetErrorCode:
        with PlainLab(open_count=0, closed_count=1) as lab:
            with pytest.raises(ConnectError) as caught:
                await AsyncioConnector(ScopeOptions()).connect(
                    "127.0.0.1", lab.closed_ports[0], timeout=10.0
                )
            return caught.value.code

    assert asyncio.run(main()) is NetErrorCode.REFUSED


def test_the_connector_works_over_ipv6_loopback_when_the_machine_has_it() -> None:
    async def main() -> tuple[bool, NetErrorCode]:
        with PlainLab(host="::1", open_count=1, closed_count=1) as lab:
            connection = await AsyncioConnector(ScopeOptions()).connect(
                "::1", lab.open_ports[0], timeout=10.0
            )
            await connection.close()
            with pytest.raises(ConnectError) as caught:
                await AsyncioConnector(ScopeOptions()).connect(
                    "::1", lab.closed_ports[0], timeout=10.0
                )
            return True, caught.value.code

    try:
        assert asyncio.run(main()) == (True, NetErrorCode.REFUSED)
    except LabError as error:
        pytest.skip(f"no IPv6 loopback on this machine: {error}")


# -- the stream wrapper, on virtual time ----------------------------------------------


class FakeWriter:
    def __init__(self, *, drain_error: OSError | None = None, close_error: OSError | None = None):
        self.written = b""
        self.closed = 0
        self._drain_error = drain_error
        self._close_error = close_error

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        if self._drain_error is not None:
            raise self._drain_error

    def close(self) -> None:
        self.closed += 1

    async def wait_closed(self) -> None:
        if self._close_error is not None:
            raise self._close_error


def wrap(reader: asyncio.StreamReader, writer: FakeWriter) -> AsyncioConnection:
    return AsyncioConnection(reader, writer)  # type: ignore[arg-type]


def test_reading_returns_what_arrived_empty_on_timeout_and_empty_at_eof() -> None:
    async def main() -> tuple[bytes, bytes, float, bytes]:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        connection = wrap(reader, FakeWriter())
        reader.feed_data(b"abc")
        first = await connection.read(2, timeout=1.0)
        second = await connection.read(10, timeout=1.0)
        quiet = await connection.read(10, timeout=2.0)  # nothing more is coming
        elapsed = loop.time()
        reader.feed_eof()
        at_eof = await connection.read(10, timeout=1.0)
        return first + second, quiet, elapsed, at_eof

    assert run_virtual(main) == (b"abc", b"", 2.0, b"")


def test_a_reset_while_reading_or_writing_is_a_normalised_error() -> None:
    async def main() -> None:
        reader = asyncio.StreamReader()
        reader.set_exception(ConnectionResetError())
        with pytest.raises(ConnectError) as read_error:
            await wrap(reader, FakeWriter()).read(1, timeout=1.0)
        assert read_error.value.code is NetErrorCode.RESET
        broken = FakeWriter(drain_error=BrokenPipeError())
        with pytest.raises(ConnectError) as write_error:
            await wrap(asyncio.StreamReader(), broken).write(b"x")
        assert write_error.value.code is NetErrorCode.RESET
        assert broken.written == b"x"

    run_virtual(main)


def test_closing_survives_a_peer_that_already_reset() -> None:
    async def main() -> int:
        writer = FakeWriter(close_error=ConnectionResetError())
        await wrap(asyncio.StreamReader(), writer).close()
        return writer.closed

    assert run_virtual(main) == 1


# -- hostile servers must not crash or hang a scan ----------------------------------------


@pytest.mark.parametrize(
    "handler", [hostile.accept_then_close, hostile.reset, hostile.silent], ids=lambda h: h.__name__
)
def test_hostile_servers_are_just_open_ports_to_a_connect_scan(handler: hostile.Handler) -> None:
    async def main() -> list[PortState]:
        spec = TargetSpec("127.0.0.1", TargetKind.IP)
        target = ResolvedTarget("127.0.0.1", "127.0.0.1", Family.IPV4, spec)
        async with (
            hostile.serve(handler) as first,
            hostile.serve(handler) as second,
            hostile.serve(handler) as third,
        ):
            async with asyncio.timeout(60):  # a failsafe against hangs, not a timing assertion
                outcome = await run_scan(
                    [target],
                    [first.port, second.port, third.port],
                    limits=Limits(connect_timeout_s=10.0),
                    connector=AsyncioConnector(ScopeOptions()),
                    limiter=NoLimit(),
                    clock=SystemClock(),
                    tool_version="test",
                )
                for server in (first, second, third):
                    await server.wait_handled(1)
        assert outcome.status is ScanStatus.COMPLETED
        return [r.state for r in outcome.report.results]

    assert asyncio.run(main()) == [PortState.OPEN] * 3


def test_a_scan_of_many_hostile_connections_does_not_leak_or_fail() -> None:
    async def main() -> int:
        spec = TargetSpec("127.0.0.1", TargetKind.IP)
        target = ResolvedTarget("127.0.0.1", "127.0.0.1", Family.IPV4, spec)
        async with hostile.serve(hostile.reset) as server:
            async with asyncio.timeout(60):
                outcome = await run_scan(
                    [target],
                    [server.port] * 200,  # 200 connections to the same resetting server
                    limits=Limits(connect_timeout_s=10.0, concurrency=32),
                    connector=AsyncioConnector(ScopeOptions()),
                    limiter=NoLimit(),
                    clock=SystemClock(),
                    tool_version="test",
                )
                await server.wait_handled(200)
        return sum(r.state is PortState.OPEN for r in outcome.report.results)

    assert asyncio.run(main()) == 200
