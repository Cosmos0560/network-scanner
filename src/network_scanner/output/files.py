"""Writing output files safely: no device paths, no symlinks, no silent overwrite, no half files.

- Device paths are refused: the Windows device names (CON, NUL, COM1 and so on, with or without
  an extension), and the POSIX device and process directories. UNC and URL forms are refused
  earlier, when the command line is parsed (`cli/common.py`).
- A symbolic link (or a Windows reparse point) at the destination is refused, with or without
  the overwrite flag. The data is never written through a path that exists: it goes into a new
  temporary file in the same directory (created exclusively, so nothing is followed), and that
  file is then renamed into place, so a symlink planted later is replaced, not followed.
- An existing file is not overwritten unless `overwrite` is true. Without it the final step is
  a hard link, which fails if the name exists, so there is no gap between check and write on
  file systems that support links; elsewhere the rename is used after a check (a rename onto an
  existing file fails on Windows and is a tiny race on POSIX, and that is documented).
- The file appears whole or not at all: the temporary file is flushed and synced before the
  rename, and removed again on any failure.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path

from network_scanner.core.errors import UsageError
from network_scanner.core.sanitize import sanitize_text

_WINDOWS_DEVICES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{n}" for n in range(1, 10)),
        *(f"LPT{n}" for n in range(1, 10)),
    }
)
_POSIX_DEVICE_PREFIXES = ("/dev/", "/proc/", "/sys/")
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT


class OutputFileError(UsageError):
    """The output path is not acceptable or the file could not be written (exit code 2)."""


def _shown(path: Path) -> str:
    return sanitize_text(path.as_posix(), max_chars=100).text


def _is_link(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)  # only Windows has this field
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT)


def check_output_path(path: Path, *, overwrite: bool) -> None:
    """Refuse a path that must not be written; the file itself is not touched."""
    posix = path.as_posix()
    if posix.startswith(_POSIX_DEVICE_PREFIXES) or posix in {
        p.rstrip("/") for p in _POSIX_DEVICE_PREFIXES
    }:
        raise OutputFileError(f"device and system paths are not accepted: {_shown(path)}")
    for part in path.parts:
        stem = part.rstrip(" .").split(".", 1)[0].upper()
        if stem in _WINDOWS_DEVICES:
            raise OutputFileError(f"device names are not accepted: {_shown(path)}")
    parent = path.parent
    if not parent.is_dir():
        raise OutputFileError(f"the directory does not exist: {_shown(parent)}")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OutputFileError(f"cannot inspect {_shown(path)} ({type(exc).__name__})") from None
    if _is_link(info):
        raise OutputFileError(f"refusing to write through a symbolic link: {_shown(path)}")
    if not stat.S_ISREG(info.st_mode):
        raise OutputFileError(f"exists and is not a regular file: {_shown(path)}")
    if not overwrite:
        raise OutputFileError(f"{_shown(path)} already exists; use --force to replace it")


def _publish(temporary: Path, path: Path, *, overwrite: bool) -> None:
    if overwrite:
        os.replace(temporary, path)
        return
    try:
        os.link(temporary, path)
    except FileExistsError:
        raise OutputFileError(f"{_shown(path)} already exists; use --force to replace it") from None
    except OSError:
        # No hard links on this file system: check, then rename (which refuses on Windows).
        check_output_path(path, overwrite=False)
        os.rename(temporary, path)
        return
    temporary.unlink()


def write_text_atomic(path: Path, text: str, *, overwrite: bool = False) -> None:
    """Write `text` (UTF-8, as given) to `path`, atomically, under the rules in the module doc."""
    check_output_path(path, overwrite=overwrite)
    data = text.encode("utf-8")
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=".network-scanner-", suffix=".tmp", dir=path.parent
        )
    except OSError as exc:
        raise OutputFileError(
            f"cannot create a file in {_shown(path.parent)} ({type(exc).__name__})"
        ) from None
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _publish(temporary, path, overwrite=overwrite)
    except OutputFileError:
        raise
    except OSError as exc:
        raise OutputFileError(f"cannot write {_shown(path)} ({type(exc).__name__})") from None
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
