"""The `scan` command: plan the targets, confirm if needed, scan, print the report.

Exit codes: 0 complete, 2 usage error or scope refusal, 3 runtime error or the total
timeout, 130 interrupted (the partial report is printed first). Output is ASCII only.

The interactive confirmation sits between two separate event-loop runs (planning, then
scanning) so that Ctrl+C at the prompt is an ordinary KeyboardInterrupt. Nothing connects
to a target in between.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from typing import Any

from network_scanner import __version__
from network_scanner.cli.common import emit, local_path
from network_scanner.cli.environment import Environment
from network_scanner.core.errors import (
    ExitCode,
    NetworkScannerError,
    ReasonCode,
    ScopeRefusal,
    UsageError,
)
from network_scanner.core.limits import Limits
from network_scanner.core.model import ResolvedTarget, ScanReport
from network_scanner.core.sanitize import sanitize_text
from network_scanner.engine.scan import ScanOutcome, ScanStatus, run_scan
from network_scanner.net.ratelimit import TokenBucket
from network_scanner.output.json_out import render_json
from network_scanner.output.table import render_table
from network_scanner.ports.spec import parse_ports
from network_scanner.scope.policy import ScopeOptions, plan_targets
from network_scanner.scope.scopefile import load_scope_file

PROMPT_LIST = 10
_COUNT = re.compile(r"[0-9]{1,6}")
_SECONDS = re.compile(r"[0-9]{1,5}(\.[0-9]{1,3})?")


def _count(text: str) -> int:
    if _COUNT.fullmatch(text) is None:
        raise argparse.ArgumentTypeError("must be a whole number of at most 6 digits")
    return int(text)


def _seconds(text: str) -> float:
    if _SECONDS.fullmatch(text) is None:
        raise argparse.ArgumentTypeError("must be a plain number of seconds, for example 2.5")
    return float(text)


def add_scan_parser(subparsers: Any) -> None:
    scan = subparsers.add_parser(
        "scan",
        help="TCP connect scan of targets you are authorized to scan",
        description=(
            "TCP connect scan. Default scope: loopback, RFC 1918, IPv6 unique-local and "
            "link-local. A public address needs --allow-public, an entry in --scope-file and "
            "confirmation. Scan only networks you own or have written permission to scan; "
            "unauthorized scanning can be illegal."
        ),
    )
    scan.add_argument("targets", nargs="+", metavar="TARGET", help="IP, CIDR, range or hostname")
    scan.add_argument("--ports", default="common", metavar="SPEC", help="default: common")
    scan.add_argument("--allow-public", action="store_true")
    scan.add_argument("--scope-file", type=local_path, metavar="PATH")
    scan.add_argument("--yes", action="store_true", help="confirm public targets in advance")
    scan.add_argument("--format", choices=("table", "json"), default="table")
    scan.add_argument("--concurrency", type=_count, metavar="N")
    scan.add_argument("--rate", type=_count, metavar="N", help="connections per second")
    scan.add_argument(
        "--connect-timeout",
        type=_seconds,
        metavar="SECONDS",
        help=(
            "per-connection timeout; a very short one can report closed ports as filtered "
            "on Windows (see docs/performance.md)"
        ),
    )
    scan.add_argument("--total-timeout", type=_seconds, metavar="SECONDS")


def _limits(args: argparse.Namespace) -> Limits:
    chosen = {
        "concurrency": args.concurrency,
        "connections_per_second": args.rate,
        "connect_timeout_s": args.connect_timeout,
        "total_timeout_s": args.total_timeout,
    }
    return Limits(**{name: value for name, value in chosen.items() if value is not None})


async def _plan(
    args: argparse.Namespace,
    options: ScopeOptions,
    limits: Limits,
    env: Environment,
    pending: list[tuple[str, ...]],
) -> tuple[ResolvedTarget, ...]:
    def defer(public: tuple[str, ...]) -> bool:
        pending.append(public)  # asked after planning, outside the event loop
        return True

    return await plan_targets(
        args.targets,
        options=options,
        limits=limits,
        resolver=env.resolver,
        confirm=defer if env.interactive else None,
    )


def _confirm(public: tuple[str, ...], env: Environment) -> None:
    shown = ", ".join(public[:PROMPT_LIST])
    more = f" and {len(public) - PROMPT_LIST} more" if len(public) > PROMPT_LIST else ""
    emit(env.stderr, f"{len(public)} public address(es) will be scanned: {shown}{more}\n")
    try:
        answer = env.ask("Type 'yes' to scan them: ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != "yes":
        raise ScopeRefusal(ReasonCode.CONFIRMATION_DECLINED, "", "confirmation declined")


async def _scan(
    targets: tuple[ResolvedTarget, ...],
    ports: tuple[int, ...],
    options: ScopeOptions,
    limits: Limits,
    env: Environment,
) -> ScanOutcome:
    limiter = TokenBucket(rate=limits.connections_per_second, clock=env.clock, sleeper=env.sleeper)
    return await run_scan(
        targets,
        ports,
        limits=limits,
        connector=env.connector_factory(options),
        limiter=limiter,
        clock=env.clock,
        tool_version=__version__,
    )


def _render(report: ScanReport, output_format: str) -> str:
    return render_json(report) if output_format == "json" else render_table(report)


def _run(args: argparse.Namespace, env: Environment) -> int:
    limits = _limits(args)
    ports = parse_ports(args.ports, max_ports=limits.max_ports_per_target)
    scope_file = load_scope_file(args.scope_file) if args.scope_file is not None else None
    options = ScopeOptions(args.allow_public, args.yes, scope_file)

    pending: list[tuple[str, ...]] = []
    targets = asyncio.run(_plan(args, options, limits, env, pending))
    for public in pending:
        _confirm(public, env)
    outcome = asyncio.run(_scan(targets, ports, options, limits, env))

    emit(env.stdout, _render(outcome.report, args.format))
    if outcome.status is ScanStatus.INTERRUPTED:
        emit(env.stderr, "interrupted: the report above is partial\n")
        return int(ExitCode.INTERRUPTED)
    if outcome.status is ScanStatus.TIMED_OUT:
        emit(env.stderr, "the total timeout was reached: the report above is partial\n")
        return int(ExitCode.RUNTIME)
    return int(ExitCode.OK)


def run_scan_command(args: argparse.Namespace, env: Environment) -> int:
    try:
        return _run(args, env)
    except KeyboardInterrupt:
        emit(env.stderr, "interrupted before the scan started\n")
        return int(ExitCode.INTERRUPTED)
    except ScopeRefusal as refusal:
        emit(env.stderr, f"refused: {refusal}\n")
        return int(ExitCode.USAGE)
    except UsageError as error:
        emit(env.stderr, f"error: {error}\n")
        return int(ExitCode.USAGE)
    except NetworkScannerError as error:
        emit(env.stderr, f"error: {sanitize_text(str(error), max_chars=300).text}\n")
        return int(ExitCode.RUNTIME)
    except Exception as error:
        message = sanitize_text(str(error), max_chars=300).text
        emit(env.stderr, f"internal error: {type(error).__name__}: {message}\n")
        return int(ExitCode.RUNTIME)
