"""Measure loopback connect latency on this machine (PLAN.md risk R2, section 0).

    python scripts/measure_connect.py [--samples N] [--concurrent N]

Question: how long does a refused connection take compared with the default connect
timeout? On Windows a closed port can take about two seconds to report a refusal; if the
timeout were shorter, a closed port would be reported as filtered.

Method, per loopback address (127.0.0.1 and ::1 only; any other host is refused):
- an OS-assigned listening socket ("open") and an OS-assigned bound-but-not-listening
  socket ("closed") are created;
- N sequential connects to each are timed with `time.perf_counter()` around
  `asyncio.open_connection`, the same call the scanner uses, on the default event loop of
  this platform, with a timeout far above anything expected so that the true latency shows;
- one batch of C concurrent connects to C closed sockets is timed as a whole.

It prints one JSON document. It makes no claim beyond the machine and the run it was made
on. The results and their interpretation live in docs/performance.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import socket
import statistics
import sys
import time
from collections.abc import Sequence
from contextlib import ExitStack
from typing import Any

from network_scanner.core.limits import DEFAULT_LIMITS

LOOPBACK_HOSTS = ("127.0.0.1", "::1")
PROBE_TIMEOUT_S = 30.0  # far above any expected latency; the aim is to see the real one


def summarise(seconds: Sequence[float]) -> dict[str, float | int]:
    """min, median and max in milliseconds, rounded to 0.1 ms."""
    ms = [value * 1000 for value in seconds]
    return {
        "samples": len(ms),
        "min_ms": round(min(ms), 1),
        "median_ms": round(statistics.median(ms), 1),
        "max_ms": round(max(ms), 1),
    }


def _bound_socket(host: str, *, listen: bool) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if sys.platform == "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((host, 0))
        if listen:
            sock.listen(socket.SOMAXCONN)
    except OSError:
        sock.close()
        raise
    return sock


async def _timed_connect(host: str, port: int) -> tuple[float, str]:
    """Seconds taken, and how it ended: "open" or the exception that ended it."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    started = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=family, flags=socket.AI_NUMERICHOST),
            PROBE_TIMEOUT_S,
        )
    except OSError as exc:
        outcome = type(exc).__name__
        winerror = getattr(exc, "winerror", None)
        if winerror is not None:
            outcome += f" (winerror {winerror})"
        return time.perf_counter() - started, outcome
    elapsed = time.perf_counter() - started
    writer.close()
    await writer.wait_closed()
    return elapsed, "open"


async def _measure_host(host: str, samples: int, concurrent: int) -> dict[str, Any]:
    with ExitStack() as stack:
        open_sock = stack.enter_context(_bound_socket(host, listen=True))
        closed_sock = stack.enter_context(_bound_socket(host, listen=False))
        batch = [stack.enter_context(_bound_socket(host, listen=False)) for _ in range(concurrent)]

        open_runs = [await _timed_connect(host, open_sock.getsockname()[1]) for _ in range(samples)]
        closed_runs = [
            await _timed_connect(host, closed_sock.getsockname()[1]) for _ in range(samples)
        ]
        started = time.perf_counter()
        batch_runs = await asyncio.gather(
            *(_timed_connect(host, sock.getsockname()[1]) for sock in batch)
        )
        batch_wall = time.perf_counter() - started

    return {
        "open": {
            **summarise([t for t, _ in open_runs]),
            "outcomes": sorted({o for _, o in open_runs}),
        },
        "closed": {
            **summarise([t for t, _ in closed_runs]),
            "outcomes": sorted({o for _, o in closed_runs}),
        },
        "closed_concurrent": {
            "connects": concurrent,
            "wall_ms": round(batch_wall * 1000, 1),
            **{k: v for k, v in summarise([t for t, _ in batch_runs]).items() if k != "samples"},
            "outcomes": sorted({o for _, o in batch_runs}),
        },
    }


async def measure(
    hosts: Sequence[str] = LOOPBACK_HOSTS, samples: int = 10, concurrent: int = 64
) -> dict[str, Any]:
    if any(host not in LOOPBACK_HOSTS for host in hosts):
        raise ValueError("only the loopback addresses 127.0.0.1 and ::1 may be measured")
    results: dict[str, Any] = {}
    for host in hosts:
        try:
            results[host] = await _measure_host(host, samples, concurrent)
        except OSError as exc:
            results[host] = {"skipped": f"cannot bind {host} here ({type(exc).__name__})"}
    slowest = max((r["closed"]["max_ms"] for r in results.values() if "closed" in r), default=None)
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "event_loop": type(asyncio.get_running_loop()).__name__,
        "default_connect_timeout_s": DEFAULT_LIMITS.connect_timeout_s,
        "slowest_refusal_ms": slowest,
        "hosts": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure loopback connect latency.")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--concurrent", type=int, default=64)
    args = parser.parse_args(argv)
    if not (1 <= args.samples <= 100 and 1 <= args.concurrent <= 256):
        parser.error("--samples must be 1-100 and --concurrent 1-256")
    result = asyncio.run(measure(samples=args.samples, concurrent=args.concurrent))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
