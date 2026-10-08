"""Writing output files: device and symlink refusal, no silent overwrite, atomic replacement."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from network_scanner.output import files
from network_scanner.output.files import OutputFileError, check_output_path, write_text_atomic


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")


def test_a_new_file_is_written_whole_and_no_temporary_file_is_left(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    write_text_atomic(target, '{"a": 1}\n')
    assert target.read_bytes() == b'{"a": 1}\n'
    assert leftovers(tmp_path) == ["report.json"]


def test_text_is_written_as_utf8_without_newline_translation(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    write_text_atomic(target, "line one\nline two\r\né")
    assert target.read_bytes() == b"line one\nline two\r\n\xc3\xa9"


def test_an_existing_file_is_not_overwritten_without_the_flag(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")
    with pytest.raises(OutputFileError, match="already exists; use --force"):
        write_text_atomic(target, "new")
    assert target.read_text(encoding="utf-8") == "original"
    assert leftovers(tmp_path) == ["report.json"]


def test_the_overwrite_flag_replaces_the_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")
    write_text_atomic(target, "new", overwrite=True)
    assert target.read_text(encoding="utf-8") == "new"
    assert leftovers(tmp_path) == ["report.json"]


def test_a_file_that_appears_after_the_check_is_still_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    real_link = os.link

    def racing_link(source: Any, destination: Any) -> None:
        Path(destination).write_text("someone else", encoding="utf-8")
        real_link(source, destination)  # now fails with FileExistsError

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(OutputFileError, match="already exists"):
        write_text_atomic(target, "mine")
    assert target.read_text(encoding="utf-8") == "someone else"
    assert leftovers(tmp_path) == ["report.json"]


def test_without_hard_links_the_file_is_renamed_into_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_links(source: Any, destination: Any) -> None:
        raise OSError(errno.EPERM, "links are not supported here")

    monkeypatch.setattr(os, "link", no_links)
    target = tmp_path / "report.json"
    write_text_atomic(target, "data")
    assert target.read_text(encoding="utf-8") == "data"
    assert leftovers(tmp_path) == ["report.json"]


def test_without_hard_links_an_existing_file_is_still_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    real_link = os.link

    def no_links(source: Any, destination: Any) -> None:
        Path(destination).write_text("someone else", encoding="utf-8")
        raise OSError(errno.EPERM, "links are not supported here")

    monkeypatch.setattr(os, "link", no_links)
    with pytest.raises(OutputFileError, match="already exists"):
        write_text_atomic(target, "mine")
    assert target.read_text(encoding="utf-8") == "someone else"
    assert leftovers(tmp_path) == ["report.json"]
    assert real_link is not None


# -- symbolic links --------------------------------------------------------------------------


@pytest.mark.parametrize("overwrite", [False, True])
def test_a_symbolic_link_is_never_followed_or_replaced(tmp_path: Path, overwrite: bool) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch", encoding="utf-8")
    link = tmp_path / "report.json"
    symlink_or_skip(link, victim)
    with pytest.raises(OutputFileError, match="symbolic link"):
        write_text_atomic(link, "payload", overwrite=overwrite)
    assert victim.read_text(encoding="utf-8") == "do not touch"
    assert link.is_symlink()
    assert leftovers(tmp_path) == ["report.json", "victim.txt"]


def test_a_dangling_symbolic_link_is_refused_too(tmp_path: Path) -> None:
    link = tmp_path / "report.json"
    symlink_or_skip(link, tmp_path / "does-not-exist")
    with pytest.raises(OutputFileError, match="symbolic link"):
        write_text_atomic(link, "payload", overwrite=True)
    assert not (tmp_path / "does-not-exist").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")
def test_a_real_junction_is_refused_like_a_symbolic_link(tmp_path: Path) -> None:
    destination = tmp_path / "elsewhere"
    destination.mkdir()
    junction = tmp_path / "report.json"
    made = subprocess.run(  # noqa: S603
        ["cmd", "/c", "mklink", "/J", str(junction), str(destination)],  # noqa: S607
        capture_output=True,
        check=False,
        timeout=60,
    )
    if made.returncode != 0:
        pytest.skip("a junction could not be created here")
    with pytest.raises(OutputFileError, match="symbolic link"):
        write_text_atomic(junction, "payload", overwrite=True)
    assert leftovers(destination) == []


def test_a_windows_reparse_point_counts_as_a_link() -> None:
    plain = SimpleNamespace(st_mode=0o100644, st_file_attributes=0x20)
    reparse = SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400)
    assert not files._is_link(plain)  # type: ignore[arg-type]
    assert files._is_link(reparse)  # type: ignore[arg-type]
    assert not files._is_link(SimpleNamespace(st_mode=0o100644))  # type: ignore[arg-type]


# -- device and system paths -----------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "NUL",
        "nul",
        "CON",
        "con.txt",
        "PRN.json",
        "AUX",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9.csv",
        "NUL .",
        "dir/NUL",
        "COM1/file.txt",
    ],
)
def test_windows_device_names_are_refused_on_every_platform(tmp_path: Path, name: str) -> None:
    with pytest.raises(OutputFileError, match="device names"):
        write_text_atomic(tmp_path / name, "x")
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("name", ["/dev/null", "/dev/stdout", "/dev", "/proc/self/mem", "/sys/x"])
def test_posix_device_and_system_paths_are_refused(name: str) -> None:
    with pytest.raises(OutputFileError, match="device and system paths"):
        write_text_atomic(Path(name), "x")


def test_names_that_only_look_like_devices_are_fine(tmp_path: Path) -> None:
    for name in ("console.txt", "nulled.txt", "com10.txt", "lpt0.txt", "auxiliary"):
        write_text_atomic(tmp_path / name, "x")
        assert (tmp_path / name).read_text(encoding="utf-8") == "x"


# -- the destination -------------------------------------------------------------------------


def test_a_missing_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(OutputFileError, match="directory does not exist"):
        write_text_atomic(tmp_path / "nope" / "report.json", "x")
    assert leftovers(tmp_path) == []


def test_a_directory_cannot_be_overwritten(tmp_path: Path) -> None:
    target = tmp_path / "folder"
    target.mkdir()
    with pytest.raises(OutputFileError, match="not a regular file"):
        write_text_atomic(target, "x", overwrite=True)


def test_checking_a_path_does_not_create_it(tmp_path: Path) -> None:
    check_output_path(tmp_path / "report.json", overwrite=False)
    assert leftovers(tmp_path) == []


def test_an_inspection_error_is_reported_without_the_system_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise PermissionError("secret system text")

    monkeypatch.setattr(Path, "lstat", broken)
    with pytest.raises(OutputFileError, match="PermissionError") as caught:
        check_output_path(tmp_path / "report.json", overwrite=False)
    assert "secret" not in str(caught.value)


def test_a_hostile_path_is_shown_sanitised(tmp_path: Path) -> None:
    with pytest.raises(OutputFileError) as caught:
        check_output_path(tmp_path / "x\x1b[31m\u202e" / "NUL", overwrite=False)
    assert "\x1b" not in str(caught.value)
    assert "\u202e" not in str(caught.value)


# -- failures leave nothing behind -----------------------------------------------------------


def test_a_failure_while_writing_leaves_no_file_and_keeps_the_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")

    def disk_full(descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "no space left")

    monkeypatch.setattr(os, "fsync", disk_full)
    with pytest.raises(OutputFileError, match="cannot write"):
        write_text_atomic(target, "new", overwrite=True)
    assert target.read_text(encoding="utf-8") == "original"
    assert leftovers(tmp_path) == ["report.json"]


def test_a_failure_to_create_the_temporary_file_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("secret system text")

    monkeypatch.setattr(tempfile, "mkstemp", refuse)
    with pytest.raises(OutputFileError, match="cannot create a file") as caught:
        write_text_atomic(tmp_path / "report.json", "x")
    assert "secret" not in str(caught.value)


def test_the_temporary_file_is_created_next_to_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    real = tempfile.mkstemp

    def recording(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("dir"))
        return real(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", recording)
    write_text_atomic(tmp_path / "report.json", "x")
    assert seen == [tmp_path]
