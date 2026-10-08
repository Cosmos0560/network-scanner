"""The `rules` command: check rule files before anything relies on them.

`rules validate [PATH ...]` loads each file through the same strict loader the scanner uses
(size cap, safe YAML, closed schema, safe regular expressions) and reports every file. With
no PATH it checks the rules built into the package. Exit codes: 0 when every file is valid,
2 when any file is invalid or unreadable (the problem is in what the user supplied). Output
is ASCII only.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from network_scanner.cli.common import emit, local_path
from network_scanner.cli.environment import Environment
from network_scanner.core.errors import ExitCode
from network_scanner.core.limits import MAX_RULE_FILE_BYTES, MAX_RULE_FILES
from network_scanner.core.sanitize import sanitize_text
from network_scanner.rules.loader import (
    builtin_finding_rules,
    builtin_fingerprint_rules,
    load_finding_rules,
    load_fingerprint_rules,
)
from network_scanner.rules.schema import RuleError

MAX_SHOWN_PATH = 120

# kind -> (rule count of a user file, rule count of the built-in file)
KINDS: dict[str, tuple[Callable[[Path], int], Callable[[], int]]] = {
    "fingerprints": (
        lambda path: len(load_fingerprint_rules(path).rules),
        lambda: len(builtin_fingerprint_rules().rules),
    ),
    "findings": (
        lambda path: len(load_finding_rules(path).rules),
        lambda: len(builtin_finding_rules().rules),
    ),
}


def add_rules_parser(subparsers: Any) -> None:
    rules = subparsers.add_parser(
        "rules",
        help="validate rule files",
        description="Work with fingerprint and finding rule files.",
    )
    actions = rules.add_subparsers(dest="rules_action", metavar="ACTION")
    validate = actions.add_parser(
        "validate",
        help="check rule files against the schema",
        description=(
            "Validate fingerprint or finding rule files: YAML is loaded with safe_load only, the "
            "schema is closed (unknown keys, wrong types and duplicate ids are refused) and "
            "every regular expression must be inside the safe subset. Files larger than "
            f"{MAX_RULE_FILE_BYTES} bytes are refused. With no PATH, the built-in rules are "
            "checked."
        ),
    )
    validate.add_argument("paths", nargs="*", type=local_path, metavar="PATH")
    validate.add_argument(
        "--kind",
        choices=sorted(KINDS),
        default="fingerprints",
        help="which kind of rule file: fingerprints (default) or findings",
    )


def _shown(path: Path) -> str:
    return sanitize_text(path.as_posix(), max_chars=MAX_SHOWN_PATH).text


def _validate(paths: list[Path], kind: str, env: Environment) -> int:
    load, builtin = KINDS[kind]
    if len(paths) > MAX_RULE_FILES:
        emit(env.stderr, f"error: more than {MAX_RULE_FILES} files in one call\n")
        return int(ExitCode.USAGE)
    failed = False
    if not paths:
        emit(env.stdout, f"OK: built-in {kind[:-1]} rules ({builtin()} rules)\n")
    for path in paths:
        try:
            count = load(path)
        except RuleError as error:
            message = sanitize_text(str(error), max_chars=400).text
            emit(env.stderr, f"INVALID: {_shown(path)}: {message}\n")
            failed = True
        else:
            emit(env.stdout, f"OK: {_shown(path)} ({count} rules)\n")
    return int(ExitCode.USAGE if failed else ExitCode.OK)


def run_rules_command(args: argparse.Namespace, env: Environment) -> int:
    if args.rules_action == "validate":
        return _validate(args.paths, args.kind, env)
    emit(env.stderr, "error: choose an action; the only one is 'validate'\n")
    return int(ExitCode.USAGE)
