from __future__ import annotations

import unicodedata

import pytest

from network_scanner.core.sanitize import sanitize_bytes, sanitize_text

BIG = 10**7
DROPPED = {"Cc", "Cf", "Cs", "Zl", "Zp"}


def clean(text: str) -> str:
    return sanitize_text(text, max_chars=BIG).text


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b[1;38;5;196mx\x1b[K", "x"),
        ("\x1b]0;window title\x07shown", "shown"),
        ("\x1b]8;;http://example.invalid\x1b\\link\x1b]8;;\x1b\\", "link"),
        ("ok\x1b]0;unterminated title", "ok"),
        ("\x1bPdevice control\x1b\\after", "after"),
        ("\x1b_apc payload\x1b\\after", "after"),
        ("\x9b31mX", "X"),
        ("\x9d0;t\x9cY", "Y"),
        ("a\x1bcb", "ab"),
        ("lone\x1b", "lone"),
    ],
)
def test_ansi_sequences_are_removed(raw: str, expected: str) -> None:
    assert clean(raw) == expected


def test_cr_and_lf_cannot_survive() -> None:
    result = clean("line1\r\nline2\rline3\nline4\x0bline5\x0cline6\ttab")
    assert not any(c in result for c in "\r\n\x0b\x0c\t")
    assert result == "line1  line2 line3 line4 line5 line6 tab"


def test_nul_and_other_controls_are_dropped() -> None:
    assert clean("a\x00b\x07c\x08d\x7fe\x85f") == "abcdef"


def test_bidi_controls_are_dropped() -> None:
    hostile = "admin\u202etxt.exe\u202c \u2066x\u2069 \u200ey\u200f \u061cz"
    assert clean(hostile) == "admintxt.exe x y z"


def test_zero_width_line_separators_and_surrogates_are_dropped() -> None:
    assert clean("a\u200bb\u2028c\u2029d\ud800e\U000e0041f\ufeffg") == "abcdefg"


def test_ordinary_text_is_unchanged() -> None:
    text = "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13 — naïve café 日本語 😀"
    assert clean(text) == text


def test_every_code_point_comes_out_safe() -> None:
    everything = "".join(map(chr, range(0x110000)))
    result = clean(everything)
    assert not any(unicodedata.category(c) in DROPPED for c in result)
    assert "\x1b" not in result


def test_invalid_utf8_becomes_replacement_characters() -> None:
    result = sanitize_bytes(b"ok\xff\xfe\x80end", max_bytes=100, max_chars=100)
    assert result.text == "ok\ufffd\ufffd\ufffdend"
    assert not result.truncated


def test_bytes_with_nul_and_ansi_are_sanitised() -> None:
    result = sanitize_bytes(b"\x1b[31mhi\x00there\r\n", max_bytes=100, max_chars=100)
    assert result.text == "hithere  "


def test_overlong_utf8_and_surrogate_encodings_are_not_decoded() -> None:
    # Overlong NUL (C0 80) and a CESU-style encoded surrogate (ED A0 80) are invalid UTF-8.
    result = sanitize_bytes(b"a\xc0\x80b\xed\xa0\x80c", max_bytes=100, max_chars=100)
    assert "\x00" not in result.text
    assert "\ud800" not in result.text
    assert result.text.startswith("a")
    assert result.text.endswith("c")


def test_text_cap_truncates_with_mark() -> None:
    result = sanitize_text("a" * 100, max_chars=10)
    assert result.text == "a" * 7 + "..."
    assert result.truncated


def test_text_cap_smaller_than_mark_still_respects_cap() -> None:
    result = sanitize_text("a" * 100, max_chars=2)
    assert result.text == ".."
    assert result.truncated


def test_text_at_cap_is_not_truncated() -> None:
    result = sanitize_text("a" * 10, max_chars=10)
    assert result.text == "a" * 10
    assert not result.truncated


def test_byte_cap_truncates_before_decoding() -> None:
    result = sanitize_bytes(b"x" * 5000, max_bytes=1024, max_chars=5000)
    assert result.text == "x" * 1024
    assert result.truncated


def test_byte_cap_cutting_a_multibyte_character_drops_the_fragment() -> None:
    result = sanitize_bytes("aé".encode(), max_bytes=2, max_chars=10)
    assert result.text == "a"
    assert result.truncated


@pytest.mark.parametrize(
    "hostile",
    [
        "\x1b[31mred\x1b[0m\r\n\x00",
        "\x1b]0;t\x07" * 20,
        "admin\u202etxt\u2066",
        "x" * 500,
        "\x1b\x00[31m",
        "\x1b[\x0031m",
    ],
)
def test_sanitising_is_idempotent(hostile: str) -> None:
    once = sanitize_text(hostile, max_chars=50)
    twice = sanitize_text(once.text, max_chars=50)
    assert twice.text == once.text


@pytest.mark.parametrize("hostile", ["\x1b\x00[31m", "\x1b[\x0031m", "\x1b\x1b[31m"])
def test_removing_a_control_cannot_assemble_an_escape_sequence(hostile: str) -> None:
    assert "\x1b" not in clean(hostile)


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param("\x1b]" + "a" * 1_000_000, id="osc-1m"),
        pytest.param("\x1b[" * 200_000, id="csi-repeated"),
        pytest.param("\x1b" + " " * 1_000_000, id="esc-spaces"),
        pytest.param("\x1b[" + "0" * 1_000_000, id="csi-params"),
        pytest.param("\x1bP" + "z" * 1_000_000, id="dcs-1m"),
    ],
)
def test_huge_hostile_input_finishes_and_respects_the_cap(hostile: str) -> None:
    result = sanitize_text(hostile, max_chars=64)
    assert len(result.text) <= 64


def test_cap_arguments_are_validated() -> None:
    with pytest.raises(ValueError, match="max_chars"):
        sanitize_text("x", max_chars=0)
    with pytest.raises(ValueError, match="max_bytes"):
        sanitize_bytes(b"x", max_bytes=0, max_chars=1)
