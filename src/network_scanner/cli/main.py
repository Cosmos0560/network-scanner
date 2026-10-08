"""Entry point for the `network-scanner` console script."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from network_scanner import __version__
from network_scanner.cli.commands.baseline import add_baseline_parser, run_baseline_command
from network_scanner.cli.commands.demo import add_demo_parser, run_demo_command
from network_scanner.cli.commands.rules import add_rules_parser, run_rules_command
from network_scanner.cli.commands.scan import add_scan_parser, run_scan_command
from network_scanner.cli.environment import Environment, default_environment
from network_scanner.core.errors import ExitCode
from network_scanner.core.sanitize import sanitize_text


class _Parser(argparse.ArgumentParser):
    """argparse echoes raw input in its error messages; strip control characters first."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        safe = sanitize_text(message, max_chars=500).text
        self.exit(int(ExitCode.USAGE), f"{self.prog}: error: {safe}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="network-scanner",
        description=(
            "Defensive TCP connect scanner and attack-surface drift monitor. "
            "Scan only networks you own or have written permission to scan; "
            "unauthorized scanning can be illegal."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    add_scan_parser(subparsers)
    add_baseline_parser(subparsers)
    add_demo_parser(subparsers)
    add_rules_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None, *, environment: Environment | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_request:
        # argparse exits on --version (0), on --help (0) and on bad usage (2).
        code = exit_request.code
        return code if isinstance(code, int) else int(ExitCode.USAGE)
    if args.command == "scan":
        return run_scan_command(args, environment or default_environment())
    if args.command == "baseline":
        return run_baseline_command(args, environment or default_environment())
    if args.command == "demo":
        return run_demo_command(args, environment or default_environment())
    if args.command == "rules":
        return run_rules_command(args, environment or default_environment())
    parser.print_help()
    return int(ExitCode.USAGE)
