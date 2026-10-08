"""`network-scanner rules validate`, through the real argument parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from network_scanner.cli.main import main
from network_scanner.core.limits import MAX_RULE_FILE_BYTES, MAX_RULE_FILES
from network_scanner.rules.loader import builtin_fingerprint_rules

GOOD = """\
schema_version: 1
rules:
  - id: one
    service: svc
    confidence: low
    description: A rule.
    match: {tls: true}
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_without_a_path_the_built_in_rules_are_checked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["rules", "validate"]) == 0
    out = capsys.readouterr()
    count = len(builtin_fingerprint_rules().rules)
    assert out.out == f"OK: built-in fingerprint rules ({count} rules)\n"
    assert out.err == ""


def test_a_valid_file_is_reported_with_its_rule_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, "good.yaml", GOOD)
    assert main(["rules", "validate", str(path)]) == 0
    assert capsys.readouterr().out == f"OK: {path.as_posix()} (1 rules)\n"


def test_an_invalid_file_is_reported_with_its_location_and_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, "bad.yaml", GOOD.replace("tls: true", "banner_regex: '(a+)+$'"))
    assert main(["rules", "validate", str(path)]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err.startswith(
        f"INVALID: {path.as_posix()}: rules[0].match.banner_regex: unsafe_regex: "
    )


def test_every_file_is_reported_and_one_bad_file_fails_the_call(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = write(tmp_path, "good.yaml", GOOD)
    unknown = write(tmp_path, "unknown.yaml", GOOD + "colour: red\n")
    duplicate = write(tmp_path, "dup.yaml", GOOD + GOOD.split("rules:\n")[1])
    missing = tmp_path / "missing.yaml"
    code = main(["rules", "validate", *(str(p) for p in (good, unknown, duplicate, missing))])
    out = capsys.readouterr()
    assert code == 2
    assert out.out == f"OK: {good.as_posix()} (1 rules)\n"
    assert f"INVALID: {unknown.as_posix()}: colour: unknown_key: " in out.err
    assert f"INVALID: {duplicate.as_posix()}: rules[1].id: duplicate_id: " in out.err
    assert f"INVALID: {missing.as_posix()}: <file>: unreadable: " in out.err


def test_an_oversized_file_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "big.yaml", "#" * (MAX_RULE_FILE_BYTES + 1))
    assert main(["rules", "validate", str(path)]) == 2
    assert "file_too_large" in capsys.readouterr().err


def test_a_directory_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "validate", str(tmp_path)]) == 2
    assert "not_a_file" in capsys.readouterr().err


def test_a_hostile_file_name_is_shown_sanitised(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    name = "x\x1b[31mred\x07.yaml"
    try:
        path = write(tmp_path, name, GOOD)
    except OSError:
        pytest.skip("this file system does not allow control characters in names")
    assert main(["rules", "validate", str(path)]) == 0
    shown = capsys.readouterr().out
    assert "\x1b" not in shown
    assert "\x07" not in shown


@pytest.mark.parametrize(
    "argument",
    [
        "\x00",
        "//server/share/rules.yaml",
        "\\\\server\\share\\rules.yaml",
        "https://example.test/r",
    ],
    ids=["nul", "unc-slash", "unc-backslash", "url"],
)
def test_hostile_paths_are_refused_before_anything_is_opened(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["rules", "validate", argument]) == 2
    assert capsys.readouterr().err


def test_too_many_files_are_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "good.yaml", GOOD)
    assert main(["rules", "validate", *([str(path)] * (MAX_RULE_FILES + 1))]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert f"more than {MAX_RULE_FILES} files" in out.err


def test_the_maximum_number_of_files_is_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, "good.yaml", GOOD)
    assert main(["rules", "validate", *([str(path)] * MAX_RULE_FILES)]) == 0
    assert capsys.readouterr().out.count("OK:") == MAX_RULE_FILES


def test_rules_without_an_action_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 2
    assert "choose an action" in capsys.readouterr().err


def test_the_help_mentions_the_safe_loading(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "validate", "--help"]) == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "safe_load only" in text
    assert f"{MAX_RULE_FILE_BYTES} bytes" in text


def test_a_path_with_control_characters_is_shown_sanitised() -> None:
    from network_scanner.cli.commands.rules import _shown

    shown = _shown(Path("dir/x\x1b[31mred\x07.yaml"))
    assert "\x1b" not in shown
    assert "\x07" not in shown
    assert shown.startswith("dir/x")
