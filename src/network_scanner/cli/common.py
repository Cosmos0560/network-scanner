"""Helpers shared by the CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO

MAX_PATH_CHARS = 4096


def local_path(text: str) -> Path:
    """A local file path. UNC, device and URL forms are refused before anything is opened."""
    if not text or len(text) > MAX_PATH_CHARS or "\x00" in text:
        raise argparse.ArgumentTypeError("not a usable file path")
    if all(char in "/\\" for char in text[:2]) and len(text) >= 2:
        raise argparse.ArgumentTypeError("network and device paths are not accepted")
    if "://" in text:
        raise argparse.ArgumentTypeError("URLs are not accepted, only local files")
    return Path(text)


def emit(stream: TextIO, text: str) -> None:
    """Write ASCII only, so no console code page can make the write fail."""
    stream.write(text.encode("ascii", "backslashreplace").decode("ascii"))
    stream.flush()
