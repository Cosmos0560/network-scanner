from __future__ import annotations

import sys
from collections.abc import Sequence

import pytest

import gate


def test_steps_cover_the_documented_gate_in_order() -> None:
    steps = gate.build_steps("py")
    assert [s.name for s in steps] == [
        "ruff check",
        "ruff format --check",
        "mypy (linux)",
        "mypy (win32)",
        "architecture check",
        "pytest + coverage",
    ]
    commands = {s.name: s.command for s in steps}
    assert commands["ruff check"] == ("py", "-m", "ruff", "check", ".")
    assert commands["ruff format --check"] == ("py", "-m", "ruff", "format", "--check", ".")
    assert commands["mypy (linux)"][-2:] == ("--platform", "linux")
    assert commands["mypy (win32)"][-2:] == ("--platform", "win32")
    assert "--cov-fail-under=85" in commands["pytest + coverage"]
    assert all(s.command[0] == "py" for s in steps)


def test_architecture_step_uses_a_posix_path() -> None:
    command = {s.name: s.command for s in gate.build_steps("py")}["architecture check"]
    assert command[1].endswith("scripts/check_architecture.py")
    assert "\\" not in command[1]


def test_all_steps_run_even_after_a_failure(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[str] = []

    def runner(command: Sequence[str]) -> int:
        seen.append(command[-1])
        return 1 if "check" in command and "ruff" in command else 0

    steps = gate.build_steps("py")
    failed = gate.run_steps(steps, runner)
    assert failed == ["ruff check"]
    assert len(seen) == len(steps)
    assert "=== gate: pytest + coverage ===" in capsys.readouterr().out


def test_main_reports_pass_and_fail(capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.main(runner=lambda command: 0) == 0
    assert "GATE PASSED" in capsys.readouterr().out
    assert gate.main(runner=lambda command: 2) == 1
    assert "GATE FAILED" in capsys.readouterr().out


def test_default_runner_returns_the_exit_status() -> None:
    assert gate._run_in_repo([sys.executable, "-c", "raise SystemExit(0)"]) == 0
    assert gate._run_in_repo([sys.executable, "-c", "raise SystemExit(3)"]) == 3
