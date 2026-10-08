"""The `demo` command: scan a lab this command starts itself, and print the report.

It takes no target. The lab is four small services (SSH-like, telnet-like, HTTP, TLS) that the
command starts on 127.0.0.1 on ports the operating system picks, scans, and stops again. The
address is a constant, the lab refuses any other host, and the planner and connector apply the
normal scope policy as well, so the demo cannot be pointed at anything else. It needs no network:
loopback is enough. The ports differ on every run (the README says so).
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

from network_scanner.cli.commands.scan import RENDERERS, add_output_arguments, deliver
from network_scanner.cli.environment import Environment
from network_scanner.cli.pipeline import (
    Prepared,
    enrich,
    exit_for_status,
    run_guarded,
    scan_prepared,
)
from network_scanner.core.errors import ExitCode
from network_scanner.core.limits import Limits
from network_scanner.engine.scan import ScanOutcome
from network_scanner.lab.services import ServiceLab
from network_scanner.output.files import check_output_path
from network_scanner.scope.policy import ScopeOptions, plan_targets

LAB_HOST = "127.0.0.1"
# The lab's services answer at once, so a short wait for the ones that never speak first (HTTP,
# TLS) is enough, and keeps the demo quick.
DEMO_LIMITS = Limits(banner_timeout_s=1.0, connect_timeout_s=10.0)


def add_demo_parser(subparsers: Any) -> None:
    demo = subparsers.add_parser(
        "demo",
        help="scan a built-in loopback lab (needs no network)",
        description=(
            "Start four small services on 127.0.0.1 (ports chosen by the operating system), scan "
            "and fingerprint them, print the report and stop them. Takes no target: it can only "
            "scan the lab it starts itself."
        ),
    )
    add_output_arguments(demo)


async def _demo(env: Environment) -> ScanOutcome:
    async with ServiceLab(host=LAB_HOST) as lab:
        options = ScopeOptions(False, False, None)
        targets = await plan_targets(
            [LAB_HOST], options=options, limits=DEMO_LIMITS, resolver=env.resolver, confirm=None
        )
        ports = tuple(sorted((lab.ssh_port, lab.telnet_port, lab.http_port, lab.tls_port)))
        return await scan_prepared(Prepared(targets, ports, options, DEMO_LIMITS), env, probe=True)


def _run(args: argparse.Namespace, env: Environment) -> int:
    if args.output is not None:
        check_output_path(args.output, overwrite=args.force)
    outcome = enrich(asyncio.run(_demo(env)))
    deliver(RENDERERS[args.format](outcome.report), args, env)
    stopped = exit_for_status(outcome.status, env)
    return int(ExitCode.OK) if stopped is None else stopped


def run_demo_command(args: argparse.Namespace, env: Environment) -> int:
    return run_guarded(lambda: _run(args, env), env)
