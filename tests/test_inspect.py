"""The probe plan, the inspector and its place in the engine, on virtual time."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from itertools import product

import pytest

from fakes import LoopClock, NoLimit
from network_scanner.core.errors import ConnectError, NetErrorCode, ReasonCode, ScopeRefusal
from network_scanner.core.limits import DEFAULT_LIMITS, TLS_HANDSHAKE_TIMEOUT_S, Limits
from network_scanner.core.model import (
    Family,
    Observation,
    PortObservation,
    PortState,
    ResolvedTarget,
    TargetKind,
    TargetSpec,
)
from network_scanner.engine.inspect import ServiceInspector
from network_scanner.engine.probe_plan import (
    TLS_FIRST_PORTS,
    ProbeAttempt,
    ProbeKind,
    next_probe,
)
from network_scanner.engine.scan import ScanStatus, run_scan
from probe_fakes import (
    HANG,
    CountingLimiter,
    FakeTlsProber,
    ScriptedStream,
    StreamConnector,
    tls_info,
)
from virtual_loop import run_virtual

pytestmark = pytest.mark.leakcheck

B, H, T = ProbeKind.BANNER, ProbeKind.HTTP_HEAD, ProbeKind.TLS
DEFAULT_BANNER_WAIT = DEFAULT_LIMITS.banner_timeout_s

# -- the plan --------------------------------------------------------------------------------


def attempts(*steps: tuple[ProbeKind, bool]) -> list[ProbeAttempt]:
    return [ProbeAttempt(kind, answered) for kind, answered in steps]


@pytest.mark.parametrize(
    ("port", "history", "expected"),
    [
        (8000, [], B),
        (8000, [(B, True)], None),  # a service that speaks first is sent nothing
        (8000, [(B, False)], H),
        (8000, [(B, False), (H, False)], T),
        (8000, [(B, False), (H, True)], None),
        (8000, [(B, False), (H, False), (T, False)], None),
        (8000, [(B, False), (H, False), (T, True)], None),
        (443, [], B),
        (443, [(B, False)], T),
        (443, [(B, False), (T, False)], H),
        (443, [(B, False), (T, True)], None),
        (443, [(B, False), (T, False), (H, False)], None),
        (22, [(B, False)], H),  # the order depends on the port, but both are tried anywhere
    ],
)
def test_the_plan_follows_the_documented_order(
    port: int, history: list[tuple[ProbeKind, bool]], expected: ProbeKind | None
) -> None:
    assert next_probe(port, attempts(*history), max_probes=3) is expected


@pytest.mark.parametrize("max_probes", [1, 2, 3])
def test_the_plan_never_exceeds_the_probe_limit(max_probes: int) -> None:
    for port in (80, 443):
        done: list[ProbeAttempt] = []
        while (kind := next_probe(port, done, max_probes=max_probes)) is not None:
            done.append(ProbeAttempt(kind, False))
        assert len(done) == max_probes
        assert len({a.kind for a in done}) == max_probes  # never the same probe twice


def test_every_possible_history_ends_and_never_repeats_a_probe() -> None:
    """Exhaustive over every answer pattern and a range of ports and limits."""
    for port, max_probes, answers in product(
        (22, 80, 443, 8443, 65535), (1, 2, 3), product((False, True), repeat=3)
    ):
        done: list[ProbeAttempt] = []
        for answer in answers:
            kind = next_probe(port, done, max_probes=max_probes)
            if kind is None:
                break
            assert kind not in {a.kind for a in done}
            done.append(ProbeAttempt(kind, answer))
        assert len(done) <= min(3, max_probes)
        if any(a.answered for a in done):
            assert next_probe(port, done, max_probes=max_probes) is None


def test_the_tls_first_ports_are_the_documented_wrapped_protocols() -> None:
    assert {443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 5061, 8443, 9443} == TLS_FIRST_PORTS


# -- the inspector ---------------------------------------------------------------------------

IP_TARGET = ResolvedTarget(
    "10.0.0.5", "10.0.0.5", Family.IPV4, TargetSpec("10.0.0.5", TargetKind.IP)
)
NAME_TARGET = ResolvedTarget(
    "lab.test", "10.0.0.5", Family.IPV4, TargetSpec("lab.test", TargetKind.HOSTNAME)
)
HEAD_REPLY = b"HTTP/1.1 200 OK\r\nServer: Lab/1.0\r\n\r\n"


def inspect(
    plan: dict[int, Sequence[ScriptedStream | BaseException | str]],
    prober: FakeTlsProber | None = None,
    *,
    port: int,
    target: ResolvedTarget = IP_TARGET,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[Observation, StreamConnector, FakeTlsProber, CountingLimiter, float]:
    connector = StreamConnector(plan)
    tls = prober or FakeTlsProber(ConnectError(NetErrorCode.OTHER))
    limiter = CountingLimiter()

    async def main() -> tuple[Observation, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        inspector = ServiceInspector(
            limits=limits,
            connector=connector,
            tls_prober=tls,
            limiter=limiter,
            tool_version="9.9.9",
        )
        return await inspector.inspect(target, port), loop.time() - started

    observation, elapsed = run_virtual(main)
    return observation, connector, tls, limiter, elapsed


def test_a_service_that_speaks_first_is_identified_with_one_connection_and_sent_nothing() -> None:
    banner = ScriptedStream([(0.0, b"SSH-2.0-Lab_1.0\r\n")])
    seen, connector, tls, limiter, _ = inspect({22: [banner]}, port=22)
    assert seen == Observation("SSH-2.0-Lab_1.0", False, "banner", None, None, None)
    assert connector.connects == [("10.0.0.5", 22)]
    assert banner.written == []
    assert banner.closed == 1
    assert tls.calls == []
    assert limiter.acquired == 1


def test_a_web_server_is_found_by_the_head_probe_after_a_silent_banner() -> None:
    silent, web = ScriptedStream(hang=True), ScriptedStream([(0.0, HEAD_REPLY)])
    seen, connector, tls, limiter, elapsed = inspect({8000: [silent, web]}, port=8000)
    assert seen == Observation(None, False, "http_head", 200, "Lab/1.0", None)
    assert [port for _, port in connector.connects] == [8000, 8000]
    assert web.written == [
        b"HEAD / HTTP/1.1\r\nHost: 10.0.0.5:8000\r\nUser-Agent: network-scanner/9.9.9\r\n"
        b"Accept: */*\r\nConnection: close\r\n\r\n"
    ]
    assert (silent.closed, web.closed) == (1, 1)
    assert tls.calls == []  # a second probe answered, so there is no third
    assert limiter.acquired == 2
    assert elapsed == DEFAULT_BANNER_WAIT  # the silent banner wait, nothing else


def test_the_host_header_carries_the_requested_name_for_a_hostname_target() -> None:
    web = ScriptedStream([(0.0, HEAD_REPLY)])
    inspect({80: [ScriptedStream(), web]}, port=80, target=NAME_TARGET)
    assert b"Host: lab.test:80\r\n" in web.written[0]


def test_a_tls_service_is_found_after_a_head_probe_that_got_no_http() -> None:
    silent, not_http = ScriptedStream(), ScriptedStream([(0.0, b"\x15\x03\x01\x00\x02\x02\x28")])
    prober = FakeTlsProber(tls_info())
    seen, connector, _, limiter, _ = inspect({9000: [silent, not_http]}, prober, port=9000)
    assert seen.probe == "tls"
    assert seen.tls == tls_info()
    assert (seen.banner, seen.http_status, seen.http_server) == (None, None, None)
    assert prober.calls == [("10.0.0.5", 9000, None, TLS_HANDSHAKE_TIMEOUT_S)]
    assert len(connector.connects) == 2  # the prober makes the third connection itself
    assert limiter.acquired == 3


def test_a_hostname_target_sends_its_name_as_the_tls_server_name() -> None:
    prober = FakeTlsProber(tls_info())
    inspect({9000: [ScriptedStream(), ScriptedStream()]}, prober, port=9000, target=NAME_TARGET)
    assert prober.calls[0][2] == "lab.test"


def test_a_port_that_is_normally_tls_tries_tls_before_http() -> None:
    prober = FakeTlsProber(tls_info())
    plan: dict[int, Sequence[ScriptedStream | BaseException | str]] = {443: [ScriptedStream()]}
    seen, connector, _, limiter, _ = inspect(plan, prober, port=443)
    assert seen.probe == "tls"
    assert len(connector.connects) == 1  # the banner only; HTTP was never needed
    assert limiter.acquired == 2


def test_a_service_nothing_answers_uses_all_three_probes_and_reports_nothing() -> None:
    prober = FakeTlsProber(ConnectError(NetErrorCode.RESET))
    seen, connector, _, limiter, elapsed = inspect(
        {7000: [ScriptedStream(hang=True), ScriptedStream(hang=True)]}, prober, port=7000
    )
    assert seen == Observation(None, False, None, None, None, None)
    assert len(connector.connects) == 2
    assert len(prober.calls) == 1
    assert limiter.acquired == 3
    assert elapsed == 2 * DEFAULT_BANNER_WAIT


@pytest.mark.parametrize(("limit", "connections", "tls_calls"), [(1, 1, 0), (2, 2, 0), (3, 2, 1)])
def test_the_probe_limit_is_honoured(limit: int, connections: int, tls_calls: int) -> None:
    streams = [ScriptedStream(), ScriptedStream()]
    prober = FakeTlsProber(ConnectError(NetErrorCode.OTHER))
    _, connector, _, limiter, _ = inspect(
        {7000: streams}, prober, port=7000, limits=Limits(probes_per_open_port=limit)
    )
    assert len(connector.connects) == connections
    assert len(prober.calls) == tls_calls
    assert limiter.acquired == limit


def test_a_banner_beyond_the_configured_cap_is_cut() -> None:
    chatty = ScriptedStream(endless=b"A")
    seen, *_ = inspect({7000: [chatty]}, port=7000, limits=Limits(banner_max_bytes=64))
    assert chatty.delivered == 64
    assert seen.banner_truncated is True
    assert seen.banner == "A" * 64


@pytest.mark.parametrize(
    "failure",
    [ConnectError(NetErrorCode.REFUSED), ConnectError(NetErrorCode.TIMEOUT), OSError("synthetic")],
    ids=["refused", "timeout", "oserror"],
)
def test_a_failed_connection_is_an_unanswered_probe(failure: BaseException) -> None:
    web = ScriptedStream([(0.0, HEAD_REPLY)])
    seen, connector, *_ = inspect({7000: [failure, web]}, port=7000)
    assert seen.probe == "http_head"  # the banner connection failed; the next probe went on
    assert len(connector.connects) == 2


def test_a_connect_that_never_finishes_is_cut_off_by_the_connect_timeout() -> None:
    web = ScriptedStream([(0.0, HEAD_REPLY)])
    seen, _, _, _, elapsed = inspect({7000: [HANG, web]}, port=7000)
    assert seen.probe == "http_head"
    assert elapsed == DEFAULT_LIMITS.connect_timeout_s


@pytest.mark.parametrize(
    "outcome", [ConnectError(NetErrorCode.OTHER), TimeoutError(), OSError("synthetic")]
)
def test_a_failed_tls_probe_is_an_unanswered_probe(outcome: BaseException) -> None:
    seen, *_ = inspect(
        {7000: [ScriptedStream(), ScriptedStream()]}, FakeTlsProber(outcome), port=7000
    )
    assert seen.probe is None
    assert seen.tls is None


def test_a_tls_probe_that_hangs_is_cut_off() -> None:
    seen, _, _, _, elapsed = inspect(
        {7000: [ScriptedStream(), ScriptedStream()]}, FakeTlsProber(HANG), port=7000
    )
    assert seen.tls is None
    assert elapsed == 2 * TLS_HANDSHAKE_TIMEOUT_S  # only the TLS guard waits


def test_a_certificate_that_could_not_be_parsed_still_counts_as_tls() -> None:
    prober = FakeTlsProber(tls_info(parse_error="malformed_certificate"))
    seen, *_ = inspect({7000: [ScriptedStream(), ScriptedStream()]}, prober, port=7000)
    assert seen.probe == "tls"
    assert seen.tls is not None
    assert seen.tls.parse_error == "malformed_certificate"


def test_a_scope_refusal_from_the_connector_is_not_swallowed() -> None:
    refusal = ScopeRefusal(ReasonCode.ALWAYS_REFUSED, "10.0.0.5", "synthetic")
    with pytest.raises(ScopeRefusal):
        inspect({7000: [refusal]}, port=7000)


def test_every_connection_is_closed_even_when_reading_fails() -> None:
    broken = ScriptedStream(read_error=NetErrorCode.RESET)
    web = ScriptedStream(write_error=NetErrorCode.RESET)
    inspect({7000: [broken, web]}, port=7000)
    assert (broken.closed, web.closed) == (1, 1)


# -- the inspector inside the scan -----------------------------------------------------------


class RecordingInspector:
    def __init__(self, hang_on: int | None = None) -> None:
        self.calls: list[tuple[str, int]] = []
        self.max_active = 0
        self._active = 0
        self._hang_on = hang_on

    async def inspect(self, target: ResolvedTarget, port: int) -> Observation:
        self.calls.append((target.address, port))
        self._active += 1
        self.max_active = max(self.max_active, self._active)
        try:
            if port == self._hang_on:
                await asyncio.sleep(10**9)
            await asyncio.sleep(1.0)
            return Observation(f"port {port}", False, "banner", None, None, None)
        finally:
            self._active -= 1


def scan_with(
    inspector: RecordingInspector | None,
    ports: Sequence[int],
    *,
    open_ports: set[int],
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[list[tuple[str, int, PortState]], tuple[PortObservation, ...], ScanStatus]:
    from fakes import Behaviour, ScriptedConnector

    connector = ScriptedConnector(
        lambda address, port: Behaviour("open" if port in open_ports else "refused")
    )
    targets = [
        ResolvedTarget(
            f"10.0.0.{n}", f"10.0.0.{n}", Family.IPV4, TargetSpec("10.0.0.0/30", TargetKind.CIDR)
        )
        for n in (2, 1)
    ]

    async def main() -> tuple[
        list[tuple[str, int, PortState]], tuple[PortObservation, ...], ScanStatus
    ]:
        outcome = await run_scan(
            targets,
            ports,
            limits=limits,
            connector=connector,
            limiter=NoLimit(),
            clock=LoopClock(),
            tool_version="9.9.9",
            inspector=inspector,
        )
        results = [(r.address, r.port, r.state) for r in outcome.report.results]
        return results, outcome.observations, outcome.status

    return run_virtual(main)


def test_without_an_inspector_a_scan_returns_no_observations() -> None:
    results, observations, status = scan_with(None, [22, 80], open_ports={22})
    assert observations == ()
    assert status is ScanStatus.COMPLETED
    assert [state for *_, state in results].count(PortState.OPEN) == 2


def test_only_open_ports_are_inspected_and_the_observations_are_ordered() -> None:
    inspector = RecordingInspector()
    results, observations, status = scan_with(inspector, [80, 22, 25], open_ports={22, 80})
    assert status is ScanStatus.COMPLETED
    assert sorted(inspector.calls) == [
        ("10.0.0.1", 22),
        ("10.0.0.1", 80),
        ("10.0.0.2", 22),
        ("10.0.0.2", 80),
    ]
    # Ordered by (position of the target in the plan, port), whatever finished first.
    assert [(o.address, o.port) for o in observations] == [
        ("10.0.0.2", 22),
        ("10.0.0.2", 80),
        ("10.0.0.1", 22),
        ("10.0.0.1", 80),
    ]
    assert observations[0].observation.banner == "port 22"
    assert len(results) == 6


def test_inspection_shares_the_concurrency_bound() -> None:
    inspector = RecordingInspector()
    scan_with(inspector, [1, 2, 3, 4, 5], open_ports={1, 2, 3, 4, 5}, limits=Limits(concurrency=2))
    assert inspector.max_active <= 2


def test_an_interrupted_inspection_keeps_the_open_result_and_the_finished_observations() -> None:
    inspector = RecordingInspector(hang_on=80)
    results, observations, status = scan_with(
        inspector, [22, 80], open_ports={22, 80}, limits=Limits(total_timeout_s=30.0)
    )
    assert status is ScanStatus.TIMED_OUT
    assert (("10.0.0.2", 80, PortState.OPEN)) in results  # recorded before inspection began
    assert [(o.address, o.port) for o in observations] == [("10.0.0.2", 22), ("10.0.0.1", 22)]
