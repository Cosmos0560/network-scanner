"""No tracked text file contains a character that hides or reorders text.

Bidirectional controls, zero-width characters and other control characters can make source or
documentation read differently from what it does ("Trojan Source"), and they are exactly what
this project's sanitiser strips from network data. Test data that needs such characters keeps
them as escapes (a backslash and a code, written out), never as the raw character.

Refused: every control character (category Cc) except tab, LF and CR; every format character
(category Cf, which holds the bidi controls U+202A-U+202E and U+2066-U+2069, the marks U+200E,
U+200F and U+061C, the zero-width characters U+200B-U+200D, U+2060 and U+FEFF, soft hyphen and
the tag characters); the line and paragraph separators (Zl, Zp); lone surrogates (Cs) and
private-use or unassigned code points (Co, Cn). The ranges are written as numbers so that this
file does not contain what it forbids.
"""

from __future__ import annotations

import subprocess
import unicodedata
from collections.abc import Iterable
from pathlib import Path

import pytest

from gitfiles import git_or_skip, tracked_files

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_CONTROLS = frozenset({0x09, 0x0A, 0x0D})
REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
NAMED = {
    **dict.fromkeys((*range(8234, 8239), *range(8294, 8298)), "bidirectional control"),
    **dict.fromkeys((8206, 8207, 1564), "bidirectional mark"),
    **dict.fromkeys((8203, 8204, 8205, 8288, 65279), "zero-width character"),
}


def describe(code: int) -> str:
    kind = NAMED.get(code) or unicodedata.category(chr(code))
    return f"U+{code:04X} ({kind})"


def find_hidden_characters(files: Iterable[tuple[str, bytes]]) -> list[str]:
    """One line per offending character: 'path:line: U+XXXX (kind)'. Binary files are skipped."""
    found = []
    for path, content in files:
        if b"\x00" in content:
            continue  # binary; none is tracked today, and a NUL would be found as text anyway
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            found.append(f"{path}: not valid UTF-8")
            continue
        for number, line in enumerate(text.split("\n"), start=1):
            for char in line:
                code = ord(char)
                if code in ALLOWED_CONTROLS:
                    continue
                if code < 0x80 and code >= 0x20 and code != 0x7F:
                    continue
                if code == 0x7F or unicodedata.category(char) in REFUSED_CATEGORIES:
                    found.append(f"{path}:{number}: {describe(code)}")
    return found


def bad(*codes: int) -> bytes:
    return ("text " + "".join(chr(code) for code in codes) + " more\n").encode("utf-8")


@pytest.mark.parametrize(
    "code",
    [
        *range(0x202A, 0x202F),  # LRE, RLE, PDF, LRO, RLO
        *range(0x2066, 0x206A),  # LRI, RLI, FSI, PDI
        0x200E,
        0x200F,
        0x061C,
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0xFEFF,
        0x00AD,
        0x2028,
        0x2029,
        0x00,
        0x01,
        0x07,
        0x08,
        0x0B,
        0x0C,
        0x1B,
        0x7F,
        0x80,
        0x9B,
        0xE000,
        0xE0041,
    ],
    ids=lambda code: f"U+{code:04X}",
)
def test_hidden_and_control_characters_are_found(code: int) -> None:
    content = bad(code)
    if code == 0x00:
        content = b"text \x00 more\n"  # a NUL marks a file as binary, which is skipped
        assert find_hidden_characters([("a.txt", content)]) == []
        return
    assert find_hidden_characters([("dir/a.txt", content)]) == [f"dir/a.txt:1: {describe(code)}"]


def test_the_line_number_and_every_offender_are_reported() -> None:
    content = b"fine\nfine\n" + bad(0x202E, 0x200B) + b"fine\n" + bad(0x1B)
    assert find_hidden_characters([("x.md", content)]) == [
        "x.md:3: U+202E (bidirectional control)",
        "x.md:3: U+200B (zero-width character)",
        "x.md:5: U+001B (Cc)",
    ]


@pytest.mark.parametrize(
    "content",
    [
        b"plain ascii\n",
        b"tab\there\r\nand CRLF\r\n",
        "caf\u00e9, na\u00efve, \u65e5\u672c\u8a9e, em dash \u2014, arrows \u2192\n".encode(),
        "emoji \U0001f600 and combining e\u0301\n".encode(),
        b"",
        b"backslash escapes stay visible: \\u202e \\x1b \\u200b\n",
    ],
    ids=["ascii", "tab-and-crlf", "ordinary-non-ascii", "emoji-and-combining", "empty", "escapes"],
)
def test_ordinary_text_is_not_flagged(content: bytes) -> None:
    assert find_hidden_characters([("a.txt", content)]) == []


def test_invalid_utf8_is_reported_and_binary_files_are_skipped() -> None:
    assert find_hidden_characters([("a.txt", b"caf\xe9\n")]) == ["a.txt: not valid UTF-8"]
    assert find_hidden_characters([("image.bin", b"\x89PNG\x00\x01\x02")]) == []


def test_a_hidden_character_in_a_file_tracked_by_git_is_detected(tmp_path: Path) -> None:
    git = git_or_skip()
    subprocess.run([git, "init", "-q"], cwd=tmp_path, check=True, timeout=60)  # noqa: S603
    (tmp_path / "clean.py").write_bytes(b"x = 1\n")
    (tmp_path / "trojan.py").write_bytes(b"access = 'user" + chr(0x202E).encode() + b"'\n")
    subprocess.run(  # noqa: S603
        [git, "add", "--", "clean.py", "trojan.py"], cwd=tmp_path, check=True, timeout=60
    )
    assert find_hidden_characters(tracked_files(tmp_path, git)) == [
        "trojan.py:1: U+202E (bidirectional control)"
    ]


def test_no_tracked_file_contains_a_hidden_or_control_character() -> None:
    git = git_or_skip()
    inside = subprocess.run(  # noqa: S603
        [git, "rev-parse", "--is-inside-work-tree"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if inside.returncode != 0:
        pytest.skip("this is not a git work tree (for example an unpacked source archive)")
    files = tracked_files(REPO_ROOT, git, include_untracked=True)
    assert len(files) > 50, "git reports too few tracked files, so the check would prove little"
    assert find_hidden_characters(files) == []


def test_a_new_file_that_is_not_tracked_yet_is_checked_when_asked(tmp_path: Path) -> None:
    git = git_or_skip()
    subprocess.run([git, "init", "-q"], cwd=tmp_path, check=True, timeout=60)  # noqa: S603
    (tmp_path / "new.py").write_bytes(b"x = '" + chr(0x202E).encode() + b"'\n")
    (tmp_path / ".gitignore").write_bytes(b"ignored.py\n")
    (tmp_path / "ignored.py").write_bytes(b"x = '" + chr(0x202E).encode() + b"'\n")
    assert find_hidden_characters(tracked_files(tmp_path, git)) == []
    found = find_hidden_characters(tracked_files(tmp_path, git, include_untracked=True))
    assert found == ["new.py:1: U+202E (bidirectional control)"]
