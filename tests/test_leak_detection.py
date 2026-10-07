"""The test run must fail on leaked sockets, loops and coroutines.

A nested pytest run uses this repository's own configuration (`pyproject.toml`) and its
`conftest.py`, on a throwaway test file that leaks on purpose.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

LEAKY_TESTS = """
import asyncio
import socket

import pytest

pytestmark = pytest.mark.leakcheck


def test_clean():
    pass


def test_leaks_a_socket():
    sock = socket.socket()
    del sock


def test_leaks_an_event_loop():
    loop = asyncio.new_event_loop()
    del loop


def test_never_awaits_a_coroutine():
    async def work():
        return 1

    work()
"""


def test_the_configuration_fails_on_leaks_and_passes_a_clean_test(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "test_leaky.py").write_text(LEAKY_TESTS, encoding="utf-8")
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(REPO_ROOT / "pyproject.toml"),
            "--rootdir",
            str(tmp_path),
            "-p",
            "no:cacheprovider",
            "-rfE",
            "-q",
            str(tmp_path / "test_leaky.py"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        cwd=tmp_path,
    )
    report = completed.stdout
    assert completed.returncode != 0, report
    for name in (
        "test_leaks_a_socket",
        "test_leaks_an_event_loop",
        "test_never_awaits_a_coroutine",
    ):
        failed = [
            line
            for line in report.splitlines()
            if name in line and line.startswith(("FAILED", "ERROR"))
        ]
        assert failed, f"{name} was not reported as a failure:\n{report}"
    assert "test_clean" not in "".join(
        line for line in report.splitlines() if line.startswith(("FAILED", "ERROR"))
    )


@pytest.mark.parametrize("option", ["filterwarnings"])
def test_the_project_turns_warnings_into_errors(option: str) -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'{option} = ["error"]' in text
