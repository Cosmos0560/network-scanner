"""The scan engine: bounded concurrency, timeouts, cancellation and ordering.

The engine opens no sockets itself. It gets a `Connector`, a `RateLimiter` and a `Clock`
and works on targets that already went through the scope plan; the connector re-checks the
policy before every connection (see `net/connector.py`).

Bounds. At most `limits.concurrency` worker tasks exist, however many probes there are: the
workers pull (target, port) pairs lazily from one shared iterator, so a large run never
creates a task or a work list per probe. Every probe has its own timeout, the run has a
total timeout, and targets x ports may not exceed `MAX_PROBES_PER_RUN`.

Outcomes. Cancellation (Ctrl+C) and the total timeout do not raise: the workers are
cancelled and awaited, and the results gathered so far come back as a report with
`complete=False` and a status that says why. Any other exception from a worker is a bug or
a policy violation and propagates after the remaining workers have been cancelled.

Results are sorted by (position of the target in the plan, port), so the report does not
depend on which probe finished first.

Inspection. If an `Inspector` is given, a worker that finds a port open hands it to the
inspector (banner, HTTP HEAD, TLS; see `inspect.py`) before taking the next probe, so the
inspection counts against the same concurrency bound and the same total timeout. The open
result is recorded first, so an interrupted inspection never loses it. Without an inspector
the behaviour is exactly the plain connect scan.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from network_scanner.core.errors import ConnectError, LimitError, NetErrorCode
from network_scanner.core.interfaces import Clock, Connector, Inspector, RateLimiter
from network_scanner.core.limits import MAX_PROBES_PER_RUN, Limits
from network_scanner.core.model import (
    SCHEMA_VERSION,
    PortObservation,
    PortResult,
    PortState,
    ResolvedTarget,
    ScanReport,
)

MAX_PORT = 65535


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"  # cancelled, normally by Ctrl+C
    TIMED_OUT = "timed_out"  # the total run timeout expired


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    report: ScanReport
    status: ScanStatus
    observations: tuple[PortObservation, ...] = ()  # only for ports found open and inspected


_STATE_FOR_ERROR = {
    NetErrorCode.REFUSED: PortState.CLOSED,
    NetErrorCode.TIMEOUT: PortState.FILTERED,
    NetErrorCode.UNREACHABLE: PortState.FILTERED,
    NetErrorCode.RESET: PortState.ERROR,
    NetErrorCode.OTHER: PortState.ERROR,
}


def state_for(code: NetErrorCode) -> PortState:
    """closed = actively refused; filtered = no answer or unreachable; error = anything else."""
    return _STATE_FOR_ERROR[code]


def _check_bounds(targets: Sequence[ResolvedTarget], ports: Sequence[int], limits: Limits) -> None:
    if not targets or not ports:
        raise LimitError("there is nothing to scan")
    if len(targets) > limits.max_targets:
        raise LimitError(f"more than {limits.max_targets} targets")
    if len(ports) > limits.max_ports_per_target:
        raise LimitError(f"more than {limits.max_ports_per_target} ports per target")
    if len(targets) * len(ports) > MAX_PROBES_PER_RUN:
        raise LimitError(f"more than {MAX_PROBES_PER_RUN} probes (targets x ports) in one run")
    if any(isinstance(p, bool) or not 1 <= p <= MAX_PORT for p in ports):
        raise LimitError("a port is outside 1-65535")


async def _probe(
    target: ResolvedTarget,
    port: int,
    *,
    limits: Limits,
    connector: Connector,
    limiter: RateLimiter,
) -> PortResult:
    await limiter.acquire()
    try:
        async with asyncio.timeout(limits.connect_timeout_s):
            connection = await connector.connect(
                target.address, port, timeout=limits.connect_timeout_s
            )
    except ConnectError as error:
        return PortResult(target.address, port, state_for(error.code), error.code)
    except TimeoutError:
        return PortResult(target.address, port, PortState.FILTERED, NetErrorCode.TIMEOUT)
    except OSError:
        return PortResult(target.address, port, PortState.ERROR, NetErrorCode.OTHER)
    await connection.close()
    return PortResult(target.address, port, PortState.OPEN, None)


async def run_scan(
    targets: Sequence[ResolvedTarget],
    ports: Sequence[int],
    *,
    limits: Limits,
    connector: Connector,
    limiter: RateLimiter,
    clock: Clock,
    tool_version: str,
    inspector: Inspector | None = None,
) -> ScanOutcome:
    """Probe every (target, port) pair and return the report and why the run ended."""
    _check_bounds(targets, ports, limits)
    started_at = clock.utc_now().isoformat()
    work = ((index, port) for index in range(len(targets)) for port in ports)
    collected: list[tuple[int, int, PortResult]] = []
    inspected: list[tuple[int, int, PortObservation]] = []

    async def worker() -> None:
        for index, port in work:  # plain iteration: nothing awaits inside the generator
            result = await _probe(
                targets[index], port, limits=limits, connector=connector, limiter=limiter
            )
            collected.append((index, port, result))
            if inspector is not None and result.state is PortState.OPEN:
                observation = await inspector.inspect(targets[index], port)
                inspected.append((index, port, PortObservation(result.address, port, observation)))

    probes = len(targets) * len(ports)
    workers = [asyncio.create_task(worker()) for _ in range(min(limits.concurrency, probes))]
    status = ScanStatus.COMPLETED
    try:
        async with asyncio.timeout(limits.total_timeout_s):
            await asyncio.gather(*workers)
    except TimeoutError:
        status = ScanStatus.TIMED_OUT
    except asyncio.CancelledError:
        status = ScanStatus.INTERRUPTED
        current = asyncio.current_task()
        if current is not None:  # pragma: no branch  (always inside a task)
            current.uncancel()  # the cancellation is handled here, by returning a report
    finally:
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    collected.sort(key=lambda item: (item[0], item[1]))
    inspected.sort(key=lambda item: (item[0], item[1]))
    report = ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=tool_version,
        started_at=started_at,
        complete=status is ScanStatus.COMPLETED,
        limits=limits,
        targets=tuple(targets),
        results=tuple(result for _, _, result in collected),
        findings=(),
    )
    return ScanOutcome(report, status, tuple(found for _, _, found in inspected))
