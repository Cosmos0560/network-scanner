"""The commit gate. Every step must pass before a commit.

    python scripts/gate.py && git commit ...

Steps (CLAUDE.md "Gate"):
1. ruff check
2. ruff format --check
3. mypy --platform linux, then mypy --platform win32
4. scripts/check_architecture.py
5. pytest with coverage (threshold 85 percent, measured over src/network_scanner and
   scripts)

All steps run even if an earlier one fails, so one run shows everything that is wrong.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_THRESHOLD = 85


@dataclass(frozen=True, slots=True)
class Step:
    name: str
    command: tuple[str, ...]


Runner = Callable[[Sequence[str]], int]


def build_steps(python: str) -> tuple[Step, ...]:
    """The gate steps, in order, as commands run with the given interpreter."""
    architecture = (REPO_ROOT / "scripts" / "check_architecture.py").as_posix()
    return (
        Step("ruff check", (python, "-m", "ruff", "check", ".")),
        Step("ruff format --check", (python, "-m", "ruff", "format", "--check", ".")),
        Step("mypy (linux)", (python, "-m", "mypy", "--platform", "linux")),
        Step("mypy (win32)", (python, "-m", "mypy", "--platform", "win32")),
        Step("architecture check", (python, architecture)),
        Step(
            "pytest + coverage",
            (
                python,
                "-m",
                "pytest",
                "--cov",
                "--cov-report=term-missing",
                f"--cov-fail-under={COVERAGE_THRESHOLD}",
            ),
        ),
    )


def _run_in_repo(command: Sequence[str]) -> int:
    return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode  # noqa: S603


def run_steps(steps: Sequence[Step], runner: Runner) -> list[str]:
    """Run every step and return the names of the ones that failed."""
    failed: list[str] = []
    for step in steps:
        print(f"\n=== gate: {step.name} ===", flush=True)
        if runner(step.command) != 0:
            failed.append(step.name)
    return failed


def main(runner: Runner = _run_in_repo) -> int:
    failed = run_steps(build_steps(sys.executable), runner)
    if failed:
        print(f"\nGATE FAILED: {', '.join(failed)}")
        return 1
    print("\nGATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
