"""The release version is one value, and every place that shows it agrees."""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest

from network_scanner import __version__
from network_scanner.cli.main import main

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def declared_version() -> str:
    """The version as pyproject.toml defines it: dynamic, read by the build backend from a file."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" in pyproject["project"]["dynamic"]
    assert "version" not in pyproject["project"], "the version must have one source"
    source = REPO_ROOT / pyproject["tool"]["hatch"]["version"]["path"]
    found = re.findall(
        r'^__version__ = "([^"]+)"$', source.read_text(encoding="utf-8"), flags=re.MULTILINE
    )
    assert len(found) == 1
    return str(found[0])


def test_the_version_pyproject_points_at_is_the_one_the_package_reports() -> None:
    assert declared_version() == __version__


def test_the_version_is_a_plain_release_number() -> None:
    assert RELEASE_VERSION.fullmatch(__version__) is not None


def test_the_command_line_reports_the_declared_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"network-scanner {declared_version()}"


def test_the_installed_metadata_has_the_declared_version() -> None:
    assert importlib.metadata.version("network-scanner") == declared_version()


def test_the_newest_changelog_entry_is_the_current_version() -> None:
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## \[([^\]]+)\](?: - (\S+))?$", changelog, flags=re.MULTILINE)
    assert headings, "the changelog has no release entry"
    newest, released = headings[0]
    assert newest == __version__
    assert released is not None
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", released)
