"""The steps that `scan`, `baseline save`, `baseline diff` and `demo` have in common.

1. `prepare`: parse the ports, load the scope file, plan the targets (scope policy, DNS, public
   confirmation). Nothing connects to a target until the whole plan is made and confirmed.
2. `execute`: run the scan, optionally with the inspector, then turn what the inspector saw into
   services (fingerprint rules) and findings (finding rules). All of that is pure decision
   logic on the data, so it is the same for every command and every output format.
3. `exit_for_status`: the exit code and message for an interrupted or timed-out run.

The interactive confirmation sits between two separate event-loop runs (planning, then
scanning) so that Ctrl+C at the prompt is an ordinary KeyboardInterrupt. Nothing connects to a
target in between.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from dataclasses import dataclass, replace
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
from network_scanner.core.model import ResolvedTarget, ScanReport, Severity
from network_scanner.core.sanitize import sanitize_text
from network_scanner.engine.inspect import ServiceInspector
from network_scanner.engine.scan import ScanOutcome, ScanStatus, run_scan
from network_scanner.findings.evaluate import evaluate_findings
from network_scanner.fingerprint.match import attach_services
from network_scanner.net.ratelimit import TokenBucket
from network_scanner.ports.spec import parse_ports
from network_scanner.rules.loader import builtin_finding_rules, builtin_fingerprint_rules
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


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """The arguments that choose what to scan and how fast; shared by every scanning command."""
    parser.add_argument("targets", nargs="+", metavar="TARGET", help="IP, CIDR, range or hostname")
    parser.add_argument("--ports", default="common", metavar="SPEC", help="default: common")
    parser.add_argument("--allow-public", action="store_true")
    parser.add_argument("--scope-file", type=local_path, metavar="PATH")
    parser.add_argument("--yes", action="store_true", help="confirm public targets in advance")
    parser.add_argument("--concurrency", type=_count, metavar="N")
    parser.add_argument("--rate", type=_count, metavar="N", help="connections per second")
    parser.add_argument(
        "--connect-timeout",
        type=_seconds,
        metavar="SECONDS",
        help=(
            "per-connection timeout; a very short one can report closed ports as filtered "
            "on Windows (see docs/performance.md)"
        ),
    )
    parser.add_argument("--total-timeout", type=_seconds, metavar="SECONDS")


def add_fail_on_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        metavar="SEVERITY",
        help="exit with code 1 if any finding is at or above this severity "
        f"({', '.join(severity.value for severity in Severity)})",
    )


def limits_from(args: argparse.Namespace) -> Limits:
    chosen = {
        "concurrency": args.concurrency,
        "connections_per_second": args.rate,
        "connect_timeout_s": args.connect_timeout,
        "total_timeout_s": args.total_timeout,
    }
    return Limits(**{name: value for name, value in chosen.items() if value is not None})


@dataclass(frozen=True, slots=True)
class Prepared:
    """A confirmed plan: every target resolved and decided, ready to scan."""

    targets: tuple[ResolvedTarget, ...]
    ports: tuple[int, ...]
    options: ScopeOptions
    limits: Limits


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


def prepare(args: argparse.Namespace, env: Environment) -> Prepared:
    limits = limits_from(args)
    ports = parse_ports(args.ports, max_ports=limits.max_ports_per_target)
    scope_file = load_scope_file(args.scope_file) if args.scope_file is not None else None
    options = ScopeOptions(args.allow_public, args.yes, scope_file)

    pending: list[tuple[str, ...]] = []
    targets = asyncio.run(_plan(args, options, limits, env, pending))
    for public in pending:
        _confirm(public, env)
    return Prepared(targets, ports, options, limits)


async def scan_prepared(prepared: Prepared, env: Environment, *, probe: bool) -> ScanOutcome:
    limits = prepared.limits
    limiter = TokenBucket(rate=limits.connections_per_second, clock=env.clock, sleeper=env.sleeper)
    connector = env.connector_factory(prepared.options)
    inspector = (
        ServiceInspector(
            limits=limits,
            connector=connector,
            tls_prober=env.tls_prober_factory(prepared.options, env.clock),
            limiter=limiter,
            tool_version=__version__,
        )
        if probe
        else None
    )
    return await run_scan(
        prepared.targets,
        prepared.ports,
        limits=limits,
        connector=connector,
        limiter=limiter,
        clock=env.clock,
        tool_version=__version__,
        inspector=inspector,
    )


def enrich(outcome: ScanOutcome) -> ScanOutcome:
    """Add services (fingerprint rules) and findings (finding rules) to a probed report."""
    report = outcome.report
    if not report.probed:
        return outcome
    observations = attach_services(report.observations, builtin_fingerprint_rules())
    findings = evaluate_findings(observations, builtin_finding_rules())
    enriched = replace(report, observations=observations, findings=findings)
    return replace(outcome, report=enriched, observations=observations)


def execute(prepared: Prepared, env: Environment, *, probe: bool) -> ScanOutcome:
    return enrich(asyncio.run(scan_prepared(prepared, env, probe=probe)))


def findings_reach(report: ScanReport, threshold: str | None) -> bool:
    """True if `--fail-on` was given and some finding is at or above that severity."""
    if threshold is None:
        return False
    level = Severity(threshold).rank
    return any(finding.severity.rank >= level for finding in report.findings)


def exit_for_status(
    status: ScanStatus, env: Environment, *, note: str = "the report above is partial"
) -> int | None:
    """The exit code (and message) for an interrupted or timed-out run; None if it completed."""
    if status is ScanStatus.INTERRUPTED:
        emit(env.stderr, f"interrupted: {note}\n")
        return int(ExitCode.INTERRUPTED)
    if status is ScanStatus.TIMED_OUT:
        emit(env.stderr, f"the total timeout was reached: {note}\n")
        return int(ExitCode.RUNTIME)
    return None


def run_guarded(action: Any, env: Environment) -> int:
    """Run `action()` and map the errors every scanning command shares onto exit codes."""
    try:
        return int(action())
    except KeyboardInterrupt:
        emit(env.stderr, "interrupted before the scan started\n")
        return int(ExitCode.INTERRUPTED)
    except ScopeRefusal as refusal:
        emit(env.stderr, f"refused: {refusal}\n")
        return int(ExitCode.USAGE)
    except UsageError as error:
        emit(env.stderr, f"error: {sanitize_text(str(error), max_chars=300).text}\n")
        return int(ExitCode.USAGE)
    except NetworkScannerError as error:
        emit(env.stderr, f"error: {sanitize_text(str(error), max_chars=300).text}\n")
        return int(ExitCode.RUNTIME)
    except Exception as error:
        message = sanitize_text(str(error), max_chars=300).text
        emit(env.stderr, f"internal error: {type(error).__name__}: {message}\n")
        return int(ExitCode.RUNTIME)
