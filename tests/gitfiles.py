"""Helpers for tests that look at the files git tracks."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

MAX_SCANNED_BYTES = 2 * 1024 * 1024


def tracked_files(root: Path, git: str) -> list[tuple[str, bytes]]:
    listing = subprocess.run(  # noqa: S603
        [git, "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert listing.returncode == 0, listing.stderr.decode("utf-8", "replace")
    files = []
    for raw in listing.stdout.split(b"\x00"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        try:
            with (root / path).open("rb") as handle:
                content = handle.read(MAX_SCANNED_BYTES)
        except OSError:
            content = b""  # deleted in the working tree; the name was still checked
        files.append((path, content))
    return files


def git_or_skip() -> str:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed, so the tracked files cannot be listed")
    return git
