"""The `scan` command: plan the targets, confirm if needed, scan, print or write the report.

Open ports are inspected by default (a passive banner read, one HTTP HEAD request, a TLS
handshake; see docs/architecture.md), then matched to services and findings. `--connect-only`
turns that off and sends nothing at all after the connection is made.

Exit codes: 0 complete and clean, 1 findings at or above `--fail-on`, 2 usage error or scope
refusal or an unacceptable output path, 3 runtime error or the total timeout, 130 interrupted
(the partial report is printed first). Output is ASCII only.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from network_scanner.cli.common import emit, local_path
from network_scanner.cli.environment import Environment
from network_scanner.cli.pipeline import (
    add_fail_on_argument,
    add_scan_arguments,
    execute,
    exit_for_status,
    findings_reach,
    prepare,
    run_guarded,
)
from network_scanner.core.errors import ExitCode
from network_scanner.core.model import ScanReport
from network_scanner.output.csv_out import render_csv
from network_scanner.output.files import check_output_path, write_text_atomic
from network_scanner.output.json_out import render_json
from network_scanner.output.jsonl import render_jsonl
from network_scanner.output.table import render_table

RENDERERS: dict[str, Callable[[ScanReport], str]] = {
    "table": render_table,
    "json": render_json,
    "jsonl": render_jsonl,
    "csv": render_csv,
}


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=sorted(RENDERERS), default="table")
    parser.add_argument(
        "--output",
        type=local_path,
        metavar="PATH",
        help="write the report to a new file instead of printing it (never through a symlink)",
    )
    parser.add_argument(
        "--force", action="store_true", help="let --output replace a file that already exists"
    )


def add_scan_parser(subparsers: Any) -> None:
    scan = subparsers.add_parser(
        "scan",
        help="TCP connect scan of targets you are authorized to scan",
        description=(
            "TCP connect scan, then a passive banner read, one HTTP HEAD request and a TLS "
            "handshake on each open port to name the service. Default scope: loopback, "
            "RFC 1918, IPv6 unique-local and link-local. A public address needs --allow-public, "
            "an entry in --scope-file and confirmation. Scan only networks you own or have "
            "written permission to scan; unauthorized scanning can be illegal."
        ),
    )
    add_scan_arguments(scan)
    add_output_arguments(scan)
    add_fail_on_argument(scan)
    scan.add_argument(
        "--connect-only",
        action="store_true",
        help="do not inspect open ports: connect, close, and send nothing",
    )


def deliver(report_text: str, args: argparse.Namespace, env: Environment) -> None:
    """Print the report, or write it to the file named by --output."""
    if args.output is None:
        emit(env.stdout, report_text)
        return
    write_text_atomic(args.output, report_text, overwrite=args.force)
    emit(env.stdout, f"report written to {_shown(args.output)}\n")


def _shown(path: Path) -> str:
    return path.as_posix()


def _run(args: argparse.Namespace, env: Environment) -> int:
    if args.output is not None:  # fail before a long scan, not after it
        check_output_path(args.output, overwrite=args.force)
    prepared = prepare(args, env)
    outcome = execute(prepared, env, probe=not args.connect_only)

    deliver(RENDERERS[args.format](outcome.report), args, env)
    stopped = exit_for_status(outcome.status, env)
    if stopped is not None:
        return stopped
    if findings_reach(outcome.report, args.fail_on):
        return int(ExitCode.FINDINGS)
    return int(ExitCode.OK)


def run_scan_command(args: argparse.Namespace, env: Environment) -> int:
    return run_guarded(lambda: _run(args, env), env)
