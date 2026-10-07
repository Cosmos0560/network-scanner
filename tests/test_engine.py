"""Engine behaviour on virtual time: no sleeping, exact numbers."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import pytest

from fakes import Behaviour, LoopClock, LoopSleeper, NoLimit, ScriptedConnector
from network_scanner.core.errors import LimitError, NetErrorCode, ScopeRefusal
from network_scanner.core.interfaces import RateLimiter
from network_scanner.core.limits import DEFAULT_LIMITS, MAX_PROBES_PER_RUN, Limits
from network_scanner.core.model import (
    SCHEMA_VERSION,
    Family,
    PortState,
    ResolvedTarget,
    TargetKind,
    TargetSpec,
    to_jsonable,
)
from network_scanner.engine.scan import ScanOutcome, ScanStatus, run_scan, state_for
from network_scanner.net.ratelimit import TokenBucket
from virtual_loop import DeadlockError, run_virtual

pytestmark = pytest.mark.leakcheck


def targets(count: int) -> list[ResolvedTarget]:
    spec = TargetSpec("10.0.0.0/24", TargetKind.CIDR)
    return [
        ResolvedTarget(
            f"10.0.{i // 250}.{i % 250 + 1}", f"10.0.{i // 250}.{i % 250 + 1}", Family.IPV4, spec
        )
        for i in range(count)
    ]


@dataclass
class Run:
    outcome: ScanOutcome
    connector: ScriptedConnector
    elapsed: float


def scan(
    target_count: int = 1,
    ports: Sequence[int] = (22,),
    *,
    script: Callable[[str, int], Behaviour] | None = None,
    limits: Limits = DEFAULT_LIMITS,
    limiter_factory: Callable[[], RateLimiter] = NoLimit,
) -> Run:
    connector = ScriptedConnector(script)

    async def main() -> Run:
        loop = asyncio.get_running_loop()
        started = loop.time()
        outcome = await run_scan(
            targets(target_count),
            ports,
            limits=limits,
            connector=connector,
            limiter=limiter_factory(),
            clock=LoopClock(),
            tool_version="9.9.9",
        )
        return Run(outcome, connector, loop.time() - started)

    return run_virtual(main)


# -- outcomes per probe --------------------------------------------------------------------


def test_every_error_code_maps_to_its_state() -> None:
    kinds = {
        1: "open",
        2: "refused",
        3: "timeout",
        4: "unreachable",
        5: "reset",
        6: "other",
        7: "oserror",
    }
    run = scan(ports=list(kinds), script=lambda address, port: Behaviour(kinds[port]))
    got = [(r.port, r.state, r.error_code) for r in run.outcome.report.results]
    assert got == [
        (1, PortState.OPEN, None),
        (2, PortState.CLOSED, NetErrorCode.REFUSED),
        (3, PortState.FILTERED, NetErrorCode.TIMEOUT),
        (4, PortState.FILTERED, NetErrorCode.UNREACHABLE),
        (5, PortState.ERROR, NetErrorCode.RESET),
        (6, PortState.ERROR, NetErrorCode.OTHER),
        (7, PortState.ERROR, NetErrorCode.OTHER),
    ]
    assert run.outcome.status is ScanStatus.COMPLETED
    assert run.connector.opened == run.connector.closed == 1


def test_state_for_covers_every_error_code() -> None:
    assert {code: state_for(code) for code in NetErrorCode} == {
        NetErrorCode.REFUSED: PortState.CLOSED,
        NetErrorCode.TIMEOUT: PortState.FILTERED,
        NetErrorCode.UNREACHABLE: PortState.FILTERED,
        NetErrorCode.RESET: PortState.ERROR,
        NetErrorCode.OTHER: PortState.ERROR,
    }


def test_results_are_ordered_by_target_then_port_whatever_finishes_first() -> None:
    # Later targets and lower ports answer faster, so completion order is the reverse.
    def script(address: str, port: int) -> Behaviour:
        return Behaviour("open", delay=100 - int(address.rsplit(".", 1)[1]) - port / 1000)

    run = scan(3, ports=[22, 80, 443], script=script)
    got = [(r.address, r.port) for r in run.outcome.report.results]
    assert got == [(f"10.0.0.{t}", p) for t in (1, 2, 3) for p in (22, 80, 443)]
    assert [a for a, _, _ in run.connector.attempts][:3] == ["10.0.0.1"] * 3


def test_the_same_run_gives_the_same_report() -> None:
    def script(address: str, port: int) -> Behaviour:
        return Behaviour(("open", "refused", "timeout")[port % 3], delay=(port * 7 % 5) / 4)

    first = scan(4, ports=range(1, 30), script=script, limits=Limits(concurrency=5))
    second = scan(4, ports=range(1, 30), script=script, limits=Limits(concurrency=5))
    assert first.outcome.report == second.outcome.report
    assert first.elapsed == second.elapsed


# -- bounds: concurrency, tasks, rate ------------------------------------------------------------


def test_concurrency_is_exactly_the_limit_and_time_follows_from_it() -> None:
    run = scan(
        5,
        ports=range(1, 21),  # 100 probes
        script=lambda address, port: Behaviour("open", delay=1.0),
        limits=Limits(concurrency=7, connect_timeout_s=30.0),
    )
    assert run.connector.max_in_flight == 7
    assert run.elapsed == 15.0  # 14 full waves of 7, then one wave of 2
    assert run.connector.max_tasks == 1 + 7  # the main task plus the workers, nothing else
    assert len(run.outcome.report.results) == 100


def test_few_probes_create_few_tasks() -> None:
    run = scan(1, ports=[1, 2, 3], limits=Limits(concurrency=64))
    assert run.connector.max_tasks == 1 + 3


def test_a_run_near_the_cap_still_uses_only_the_worker_tasks() -> None:
    limits = Limits(max_targets=1000, concurrency=512)
    run = scan(1000, ports=range(1, 21), limits=limits)  # 20,000 probes
    assert len(run.connector.attempts) == 20_000
    assert run.connector.max_tasks == 1 + 512
    assert run.connector.max_in_flight <= 512


def test_the_rate_limiter_spaces_connection_starts_exactly() -> None:
    def bucket() -> TokenBucket:
        return TokenBucket(rate=4, clock=LoopClock(), sleeper=LoopSleeper())

    run = scan(1, ports=range(1, 9), limiter_factory=bucket, limits=Limits(concurrency=8))
    starts = sorted(t for _, _, t in run.connector.attempts)
    assert starts == [0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75]
    assert run.elapsed == 1.75


# -- timeouts ---------------------------------------------------------------------------------


def test_a_connector_that_never_answers_is_cut_off_by_the_probe_timeout() -> None:
    def script(address: str, port: int) -> Behaviour:
        return Behaviour("hang") if port == 1 else Behaviour("open", delay=1.0)

    run = scan(ports=[1, 2], script=script, limits=Limits(connect_timeout_s=3.0))
    first, second = run.outcome.report.results
    assert (first.state, first.error_code) == (PortState.FILTERED, NetErrorCode.TIMEOUT)
    assert second.state is PortState.OPEN
    assert run.elapsed == 3.0
    assert run.connector.in_flight == 0


def test_the_total_timeout_returns_the_partial_report() -> None:
    run = scan(
        ports=range(1, 11),
        script=lambda address, port: Behaviour("open", delay=1.0),
        limits=Limits(concurrency=1, total_timeout_s=3.5, connect_timeout_s=30.0),
    )
    report = run.outcome.report
    assert run.outcome.status is ScanStatus.TIMED_OUT
    assert report.complete is False
    assert [r.port for r in report.results] == [1, 2, 3]
    assert run.elapsed == 3.5
    assert run.connector.in_flight == 0


@pytest.mark.parametrize(
    ("total_timeout", "status", "ports"),
    [
        (2.999, ScanStatus.TIMED_OUT, [1, 2]),
        (3.0, ScanStatus.TIMED_OUT, [1, 2]),  # a tie goes to the timeout
        (3.001, ScanStatus.COMPLETED, [1, 2, 3]),
    ],
)
def test_the_total_timeout_boundary_is_exact(
    total_timeout: float, status: ScanStatus, ports: list[int]
) -> None:
    run = scan(
        ports=range(1, 4),
        script=lambda address, port: Behaviour("open", delay=1.0),
        limits=Limits(concurrency=1, total_timeout_s=total_timeout, connect_timeout_s=30.0),
    )
    assert run.outcome.status is status
    assert [r.port for r in run.outcome.report.results] == ports


# -- cancellation -----------------------------------------------------------------------------


def cancelled_run(cancel_at: float) -> tuple[ScanOutcome, ScriptedConnector, int]:
    connector = ScriptedConnector(lambda address, port: Behaviour("open", delay=1.0))
    limits = Limits(concurrency=1, connect_timeout_s=30.0)

    async def main() -> tuple[ScanOutcome, int]:
        task = asyncio.create_task(
            run_scan(
                targets(1),
                range(1, 11),
                limits=limits,
                connector=connector,
                limiter=NoLimit(),
                clock=LoopClock(),
                tool_version="9.9.9",
            )
        )
        await asyncio.sleep(cancel_at)
        task.cancel()
        outcome = await task  # the engine handles the cancellation and returns normally
        return outcome, task.cancelling()

    outcome, pending_cancellations = run_virtual(main)
    return outcome, connector, pending_cancellations


def test_cancellation_returns_the_partial_report_and_cleans_up() -> None:
    outcome, connector, pending = cancelled_run(2.5)
    assert outcome.status is ScanStatus.INTERRUPTED
    assert outcome.report.complete is False
    assert [r.port for r in outcome.report.results] == [1, 2]
    assert connector.in_flight == 0
    assert pending == 0  # the cancellation was consumed, not left half-handled


def test_cancellation_before_anything_finished_gives_an_empty_partial_report() -> None:
    outcome, _, _ = cancelled_run(0.5)
    assert outcome.status is ScanStatus.INTERRUPTED
    assert outcome.report.results == ()


# -- errors propagate -------------------------------------------------------------------------


def test_an_unexpected_exception_aborts_the_run_and_leaves_no_task_behind() -> None:
    connector = ScriptedConnector(
        lambda address, port: Behaviour("bug") if port == 5 else Behaviour("open", delay=2.0)
    )

    async def main() -> None:
        await run_scan(
            targets(3),
            range(1, 30),
            limits=Limits(concurrency=4),
            connector=connector,
            limiter=NoLimit(),
            clock=LoopClock(),
            tool_version="9.9.9",
        )

    with pytest.raises(RuntimeError, match="synthetic bug"):
        run_virtual(main)
    assert connector.in_flight == 0


def test_a_policy_refusal_from_the_connector_aborts_the_run() -> None:
    connector = ScriptedConnector(lambda address, port: Behaviour("policy"))

    async def main() -> None:
        await run_scan(
            targets(1),
            [22],
            limits=DEFAULT_LIMITS,
            connector=connector,
            limiter=NoLimit(),
            clock=LoopClock(),
            tool_version="9.9.9",
        )

    with pytest.raises(ScopeRefusal):
        run_virtual(main)


def test_the_test_loop_turns_a_real_deadlock_into_a_failure_not_a_hang() -> None:
    async def main() -> None:
        await asyncio.Event().wait()

    with pytest.raises(DeadlockError):
        run_virtual(main)


# -- bounds are checked before any work -----------------------------------------------------------


@pytest.mark.parametrize(
    ("target_count", "ports", "limits"),
    [
        (0, [22], DEFAULT_LIMITS),
        (1, [], DEFAULT_LIMITS),
        (3, [22], Limits(max_targets=2)),
        (1, [1, 2, 3], Limits(max_ports_per_target=2)),
        (4096, range(1, 27), Limits(max_targets=4096, max_ports_per_target=1024)),
        (1, [0], DEFAULT_LIMITS),
        (1, [65536], DEFAULT_LIMITS),
        (1, [-1], DEFAULT_LIMITS),
        (1, [True], DEFAULT_LIMITS),
    ],
    ids=[
        "no-targets",
        "no-ports",
        "too-many-targets",
        "too-many-ports",
        "too-many-probes",
        "port-0",
        "port-65536",
        "negative-port",
        "bool-port",
    ],
)
def test_out_of_bounds_runs_are_refused_before_anything_is_attempted(
    target_count: int, ports: Sequence[int], limits: Limits
) -> None:
    connector = ScriptedConnector()

    async def main() -> None:
        await run_scan(
            targets(target_count),
            ports,
            limits=limits,
            connector=connector,
            limiter=NoLimit(),
            clock=LoopClock(),
            tool_version="9.9.9",
        )

    with pytest.raises(LimitError):
        run_virtual(main)
    assert connector.attempts == []


def test_the_probe_cap_is_a_constant_of_the_package() -> None:
    assert MAX_PROBES_PER_RUN == 100_000


# -- the report -------------------------------------------------------------------------------


def test_the_report_carries_its_inputs_and_serialises() -> None:
    run = scan(2, ports=[22, 80], limits=Limits(concurrency=3))
    report = run.outcome.report
    assert report.schema_version == SCHEMA_VERSION
    assert report.tool_version == "9.9.9"
    assert report.started_at == "2026-01-01T12:00:00+00:00"
    assert report.complete is True
    assert report.limits == Limits(concurrency=3)
    assert [t.address for t in report.targets] == ["10.0.0.1", "10.0.0.2"]
    assert report.findings == ()
    data = json.loads(json.dumps(to_jsonable(report)))
    assert data["results"][0] == {
        "address": "10.0.0.1",
        "port": 22,
        "state": "open",
        "error_code": None,
    }
