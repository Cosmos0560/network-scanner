from __future__ import annotations

from pathlib import Path

import pytest

from network_scanner.core.errors import ScopeFileError
from network_scanner.core.limits import MAX_SCOPE_ENTRIES, MAX_SCOPE_FILE_BYTES
from network_scanner.core.model import Family
from network_scanner.scope.parser import Address, parse_ip
from network_scanner.scope.scopefile import (
    ScopeEntry,
    ScopeFile,
    load_scope_file,
    parse_scope_bytes,
    parse_scope_text,
)

NBSP = chr(0xA0)
BIDI = chr(0x202E)
ZWSP = chr(0x200B)
BOM = chr(0xFEFF)


def error_of(text: str) -> ScopeFileError:
    with pytest.raises(ScopeFileError) as caught:
        parse_scope_text(text)
    return caught.value


# -- accepted content -----------------------------------------------------------------------


def test_a_typical_file_is_parsed() -> None:
    scope = parse_scope_text(
        "# lab scope\n"
        "\n"
        "8.8.8.0/24   # a public block of 256\n"
        "  203.0.114.7\t\n"
        "10.0.0.0/8\n"
        "2606:4700::/120\n"
    )
    assert [e.raw for e in scope.entries] == [
        "8.8.8.0/24",
        "203.0.114.7",
        "10.0.0.0/8",
        "2606:4700::/120",
    ]
    assert scope.contains(parse_ip("8.8.8.0"))
    assert scope.contains(parse_ip("8.8.8.255"))
    assert not scope.contains(parse_ip("8.8.9.0"))
    assert not scope.contains(parse_ip("8.8.7.255"))
    assert scope.contains(parse_ip("203.0.114.7"))
    assert not scope.contains(parse_ip("203.0.114.8"))
    assert scope.contains(parse_ip("2606:4700::ff"))
    assert not scope.contains(parse_ip("2606:4700::100"))


def test_crlf_bom_blank_files_and_a_missing_final_newline_are_fine() -> None:
    assert parse_scope_text("").entries == ()
    assert parse_scope_text("\n\n# nothing\n").entries == ()
    crlf = parse_scope_text("8.8.8.8\r\n8.8.4.4\r\n")
    assert [e.raw for e in crlf.entries] == ["8.8.8.8", "8.8.4.4"]
    assert parse_scope_text("8.8.8.8").entries[0].raw == "8.8.8.8"
    assert parse_scope_bytes(b"\xef\xbb\xbf8.8.8.8\n").entries[0].raw == "8.8.8.8"


def test_narrow_and_wide_private_entries_are_accepted() -> None:
    scope = parse_scope_text("10.0.0.0/8\n192.168.0.0/16\nfd00::/8\n8.8.8.8/32\n8.8.8.0/24\n")
    assert len(scope.entries) == 5


def test_the_widest_public_entries_are_exactly_slash_24_and_slash_120() -> None:
    assert error_of("8.8.0.0/23\n").line == 1
    assert error_of("2606:4700::/119\n").line == 1
    parse_scope_text("8.8.8.0/24\n2606:4700::/120\n")


def test_entries_overlap_and_merge_for_lookups() -> None:
    scope = parse_scope_text("8.8.8.0/25\n8.8.8.128/25\n8.8.8.64/26\n8.8.9.0/24\n")
    assert scope.merged_v4 == ((parse_ip("8.8.8.0").value, parse_ip("8.8.9.255").value),)
    assert scope.contains(parse_ip("8.8.9.255"))
    assert not scope.contains(parse_ip("8.8.10.0"))


def test_contains_is_false_for_the_other_family_and_for_an_empty_file() -> None:
    scope = parse_scope_text("8.8.8.8\n")
    assert not scope.contains(parse_ip("::808:808"))
    assert not ScopeFile.of(()).contains(parse_ip("8.8.8.8"))
    assert not scope.contains(Address(Family.IPV4, 0))


def test_scope_file_of_builds_from_entries() -> None:
    entry = ScopeEntry("x", Family.IPV4, 5, 9)
    scope = ScopeFile.of([entry])
    assert scope.merged_v4 == ((5, 9),)
    assert scope.contains(Address(Family.IPV4, 9))
    assert not scope.contains(Address(Family.IPV4, 10))


# -- refused content, with the line number -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "line", "fragment"),
    [
        ("example.com\n", 1, "only IP addresses and CIDR"),
        ("# ok\n\n10.0.0.1-5\n", 3, "only IP addresses and CIDR"),
        ("8.8.8.8 8.8.4.4\n", 1, "one entry per line"),
        ("8.8.8.8\t8.8.4.4\n", 1, "one entry per line"),
        ("fe80::1%eth0\n", 1, "zone ids"),
        ("8.8.0.0/16\n", 1, "/24 or narrower"),
        ("1.0.0.0/8\n", 1, "/24 or narrower"),
        ("100.64.0.0/10\n", 1, "/24 or narrower"),  # CGNAT is public (decision D4)
        ("2001:4860::/32\n", 1, "/120 or narrower"),
        ("224.0.0.0/24\n", 1, "always-refused addresses (multicast)"),
        ("169.254.169.254\n", 1, "always-refused addresses (link_local_v4)"),
        ("192.0.2.0/24\n", 1, "always-refused addresses (documentation)"),
        ("0.0.0.0/0\n", 1, "always-refused"),
        ("::/0\n", 1, "always-refused"),
        ("::ffff:10.0.0.1\n", 1, "always-refused addresses (embedded_ipv4)"),
        ("0x7f.0.0.1\n", 1, "ambiguous_numeric"),
        ("10.0.0.5/24\n", 1, "cidr_host_bits"),
        ("8.8.8.8\n\n\n127.1\n", 4, "ambiguous_numeric"),
        ("8.8.8.8\n[::1]\n", 2, "invalid_target"),
    ],
)
def test_invalid_entries_are_refused_with_a_line_number(
    text: str, line: int, fragment: str
) -> None:
    error = error_of(text)
    assert error.line == line
    assert fragment in error.detail
    assert str(error).startswith(f"line {line}: ")


@pytest.mark.parametrize(
    "text",
    [
        "8.8.8.8\x00\n",
        "# comment with nul \x00\n",
        f"# trojan {BIDI} source\n",
        f"8.8.8.8 # hidden {ZWSP} char\n",
        f"{NBSP}8.8.8.8\n",
        "8.8.8.8\r8.8.4.4\n",
        "8.8.8.8\x1b[31m\n",
        f"8.8.8.8\n{BOM}8.8.4.4\n",
        "8.8.8.8\x7f\n",
    ],
    ids=[
        "nul",
        "nul-in-comment",
        "bidi",
        "zero-width",
        "nbsp",
        "lone-cr",
        "ansi",
        "bom-mid-file",
        "del",
    ],
)
def test_control_and_format_characters_are_refused_even_inside_comments(text: str) -> None:
    error = error_of(text)
    assert "control or format character" in error.detail
    assert not any(c in str(error) for c in "\x00\x1b" + BIDI + ZWSP + "\r")


def test_entry_count_is_capped() -> None:
    ok = "\n".join(f"10.{i // 256}.{i % 256}.0/24" for i in range(MAX_SCOPE_ENTRIES))
    assert len(parse_scope_text(ok).entries) == MAX_SCOPE_ENTRIES
    error = error_of(ok + "\n10.200.0.0/24\n")
    assert "more than" in error.detail
    assert error.line == MAX_SCOPE_ENTRIES + 1


# -- bytes and files -------------------------------------------------------------------------


def test_size_and_encoding_limits() -> None:
    parse_scope_bytes(b"#" * (MAX_SCOPE_FILE_BYTES - 1) + b"\n")
    with pytest.raises(ScopeFileError, match="larger than"):
        parse_scope_bytes(b"#" * (MAX_SCOPE_FILE_BYTES + 1))
    with pytest.raises(ScopeFileError, match="not valid UTF-8"):
        parse_scope_bytes(b"8.8.8.8\n\xff\xfe\n")
    with pytest.raises(ScopeFileError, match="not valid UTF-8"):
        parse_scope_bytes(b"\xc0\x80\n")  # overlong NUL


def test_load_scope_file_reads_a_real_file(tmp_path: Path) -> None:
    path = tmp_path / "scope.txt"
    path.write_text("# scope\n8.8.8.0/24\n", encoding="utf-8")
    assert load_scope_file(path).contains(parse_ip("8.8.8.8"))


def test_load_scope_file_refuses_an_oversized_file_after_reading_only_the_cap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "big.txt"
    path.write_bytes(b"#" * (MAX_SCOPE_FILE_BYTES * 20))
    with pytest.raises(ScopeFileError, match="larger than"):
        load_scope_file(path)


def test_load_scope_file_reports_unreadable_paths_without_leaking_details(
    tmp_path: Path,
) -> None:
    for path in (tmp_path / "missing.txt", tmp_path):
        with pytest.raises(ScopeFileError, match=r"cannot read the scope file \(\w+\)") as caught:
            load_scope_file(path)
        assert str(tmp_path.name) not in str(caught.value)
