"""Entry point for the `network-scanner` console script."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from network_scanner import __version__
from network_scanner.core.errors import ExitCode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-scanner",
        description=(
            "Defensive TCP connect scanner and attack-surface drift monitor. "
            "Scan only networks you own or have written permission to scan; "
            "unauthorized scanning can be illegal."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exit_request:
        # argparse exits on --version (0), on --help (0) and on bad usage (2).
        code = exit_request.code
        return code if isinstance(code, int) else int(ExitCode.USAGE)
    parser.print_help()
    return int(ExitCode.USAGE)
