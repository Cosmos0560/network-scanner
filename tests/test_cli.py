from __future__ import annotations

import importlib
import importlib.metadata
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from network_scanner import __version__
from network_scanner.cli.main import main

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_version_flag_prints_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"network-scanner {__version__}"


def test_no_arguments_prints_help_and_exits_with_usage_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 2
    out = " ".join(capsys.readouterr().out.split())
    assert "usage: network-scanner" in out
    assert "unauthorized scanning can be illegal" in out


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    assert "--version" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["--bogus"], id="unknown-flag"),
        pytest.param(["\x00"], id="nul"),
        pytest.param(["--version=1"], id="flag-with-value"),
        pytest.param(["x" * 100_000], id="huge-positional"),
    ],
)
def test_bad_arguments_exit_with_usage_code(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == 2
    assert capsys.readouterr().err


def test_package_version_matches_installed_metadata() -> None:
    assert importlib.metadata.version("network-scanner") == __version__


def test_console_script_points_at_main() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    target = pyproject["project"]["scripts"]["network-scanner"]
    module_name, _, attribute = target.partition(":")
    assert getattr(importlib.import_module(module_name), attribute) is main


def test_version_in_a_real_process() -> None:
    code = "import sys; from network_scanner.cli.main import main; sys.exit(main(['--version']))"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, timeout=60
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"network-scanner {__version__}"


def test_the_default_environment_wires_the_real_adapters() -> None:
    from network_scanner.cli.environment import default_environment
    from network_scanner.net.connector import AsyncioConnector
    from network_scanner.net.resolver import SystemResolver
    from network_scanner.net.system import AsyncioSleeper, SystemClock
    from network_scanner.scope.policy import ScopeOptions

    env = default_environment()
    assert isinstance(env.resolver, SystemResolver)
    assert isinstance(env.clock, SystemClock)
    assert isinstance(env.sleeper, AsyncioSleeper)
    assert isinstance(env.connector_factory(ScopeOptions()), AsyncioConnector)
    assert isinstance(env.interactive, bool)
    assert env.ask is input
