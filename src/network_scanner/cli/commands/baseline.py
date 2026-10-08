"""The `baseline` command: save what a scan found, and later report the drift from it.

`baseline save TARGET... --baseline FILE` scans (with fingerprinting) and writes the open ports
and services to FILE. It refuses a scan that did not complete, because a partial scan would
turn every port it missed into "closed" later, and it will not replace an existing file unless
`--force` is given.

`baseline diff TARGET... --baseline FILE` reads FILE first (it is untrusted input and a bad
file should fail before a long scan, not after it), scans, and reports what is new, closed or
changed since, plus entries the scan did not cover. Exit codes: 0 no drift, 1 drift (or findings
at or above `--fail-on`), 2 usage error, scope refusal or an unacceptable baseline file, 3
runtime error or the total timeout, 130 interrupted. A scan that did not complete gives no drift
report, only that exit code.
"""

from __future__ import annotations

import argparse
from typing import Any

from network_scanner.baseline.diff import diff_baselines, has_drift
from network_scanner.baseline.store import build_baseline, load_baseline, render_baseline
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
from network_scanner.output.drift import render_drift_json, render_drift_table
from network_scanner.output.files import check_output_path, write_text_atomic

DRIFT_RENDERERS = {"table": render_drift_table, "json": render_drift_json}


def add_baseline_parser(subparsers: Any) -> None:
    baseline = subparsers.add_parser(
        "baseline",
        help="save a baseline of open ports and services, and report drift from it",
        description=(
            "Attack-surface drift monitoring. Scan only networks you own or have written "
            "permission to scan; unauthorized scanning can be illegal."
        ),
    )
    actions = baseline.add_subparsers(dest="baseline_action", metavar="ACTION")

    save = actions.add_parser(
        "save",
        help="scan and save the open ports and their services",
        description="Scan, fingerprint the open ports and write them to the baseline file.",
    )
    add_scan_arguments(save)
    save.add_argument("--baseline", type=local_path, required=True, metavar="PATH")
    save.add_argument(
        "--force", action="store_true", help="replace the baseline file if it already exists"
    )

    diff = actions.add_parser(
        "diff",
        help="scan and report what changed since the baseline",
        description=(
            "Scan, fingerprint the open ports and compare them with the baseline file. Exit "
            "code 1 means drift was found."
        ),
    )
    add_scan_arguments(diff)
    diff.add_argument("--baseline", type=local_path, required=True, metavar="PATH")
    diff.add_argument("--format", choices=sorted(DRIFT_RENDERERS), default="table")
    add_fail_on_argument(diff)


def _save(args: argparse.Namespace, env: Environment) -> int:
    check_output_path(args.baseline, overwrite=args.force)
    outcome = execute(prepare(args, env), env, probe=True)
    stopped = exit_for_status(outcome.status, env, note="no baseline was written")
    if stopped is not None:
        return stopped
    baseline = build_baseline(outcome.report)
    write_text_atomic(args.baseline, render_baseline(baseline), overwrite=args.force)
    emit(
        env.stdout,
        f"baseline saved: {len(baseline.entries)} open port(s) -> {args.baseline.as_posix()}\n",
    )
    return int(ExitCode.OK)


def _diff(args: argparse.Namespace, env: Environment) -> int:
    saved = load_baseline(args.baseline)
    outcome = execute(prepare(args, env), env, probe=True)
    stopped = exit_for_status(outcome.status, env, note="no drift was computed")
    if stopped is not None:
        return stopped
    report = outcome.report
    probed = {(result.address, result.port) for result in report.results}
    drift = diff_baselines(saved, build_baseline(report), probed)
    emit(env.stdout, DRIFT_RENDERERS[args.format](drift, report.findings))
    if has_drift(drift) or findings_reach(report, args.fail_on):
        return int(ExitCode.FINDINGS)
    return int(ExitCode.OK)


def run_baseline_command(args: argparse.Namespace, env: Environment) -> int:
    if args.baseline_action == "save":
        return run_guarded(lambda: _save(args, env), env)
    if args.baseline_action == "diff":
        return run_guarded(lambda: _diff(args, env), env)
    emit(env.stderr, "error: choose an action: save or diff\n")
    return int(ExitCode.USAGE)
