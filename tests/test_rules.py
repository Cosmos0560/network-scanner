"""Rule files: schema, error codes, loading from disk, and the built-in fingerprint rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from network_scanner.core.limits import MAX_RULE_FILE_BYTES, MAX_RULES
from network_scanner.core.model import Confidence
from network_scanner.rules import loader as loader_module
from network_scanner.rules.loader import builtin_fingerprint_rules, load_fingerprint_rules
from network_scanner.rules.schema import RuleError, RuleErrorCode, parse_fingerprint_rules

VALID = """\
schema_version: 1
rules:
  - id: ssh-id
    service: ssh
    confidence: high
    description: SSH identification string.
    match:
      banner_regex: '^SSH-[0-9]\\.[0-9]+-'
  - id: web
    service: http
    confidence: medium
    description: An HTTP status line, served by something called nginx.
    match:
      http_response: true
      http_server_regex: '^nginx'
      tls: true
"""


def error_of(text: str) -> RuleError:
    with pytest.raises(RuleError) as caught:
        parse_fingerprint_rules(text)
    return caught.value


def replaced(old: str, new: str) -> str:
    assert old in VALID
    return VALID.replace(old, new)


def test_a_valid_document_parses_in_file_order() -> None:
    rules = parse_fingerprint_rules(VALID).rules
    assert [r.id for r in rules] == ["ssh-id", "web"]
    first, second = rules
    assert (first.service, first.confidence, first.banner_regex) == (
        "ssh",
        Confidence.HIGH,
        "^SSH-[0-9]\\.[0-9]+-",
    )
    assert first.banner_pattern is not None
    assert not first.http_response
    assert not first.tls
    assert (second.http_response, second.tls, second.http_server_regex) == (True, True, "^nginx")
    assert second.http_server_pattern is not None


# Each case: the changed document, the expected code, and where the error points.
CASES = [
    # unknown fields
    (VALID + "extra: 1\n", RuleErrorCode.UNKNOWN_KEY, "extra"),
    (
        replaced("    service: ssh\n", "    service: ssh\n    colour: red\n"),
        "unknown_key",
        "rules[0].colour",
    ),
    (
        replaced("      http_response: true\n", "      http_response: true\n      port: 80\n"),
        "unknown_key",
        "rules[1].match.port",
    ),
    (replaced("  - id: web", "  - 7: seven\n  - id: web"), "unknown_key", "rules[1]"),
    # missing fields
    ("rules: []\n", "missing_key", "<file>"),
    ("schema_version: 1\n", "missing_key", "<file>"),
    (replaced("    description: SSH identification string.\n", ""), "missing_key", "rules[0]"),
    (replaced("    confidence: high\n", ""), "missing_key", "rules[0]"),
    (
        replaced("    match:\n      banner_regex: '^SSH-[0-9]\\.[0-9]+-'\n", ""),
        "missing_key",
        "rules[0]",
    ),
    # wrong types
    ("- 1\n", "wrong_type", "<file>"),
    ("just text", "wrong_type", "<file>"),
    ("", "wrong_type", "<file>"),
    ("schema_version: '1'\nrules: []\n", "wrong_type", "schema_version"),
    ("schema_version: true\nrules: []\n", "wrong_type", "schema_version"),
    ("schema_version: 1\nrules: nope\n", "wrong_type", "rules"),
    ("schema_version: 1\nrules: [1]\n", "wrong_type", "rules[0]"),
    (replaced("id: ssh-id", "id: 5"), "wrong_type", "rules[0].id"),
    (replaced("service: ssh", "service: [ssh]"), "wrong_type", "rules[0].service"),
    (replaced("confidence: high", "confidence: 3"), "wrong_type", "rules[0].confidence"),
    (
        replaced("banner_regex: '^SSH-[0-9]\\.[0-9]+-'", "banner_regex: 5"),
        "wrong_type",
        "rules[0].match.banner_regex",
    ),
    (
        replaced("http_response: true", "http_response: 'yes'"),
        "wrong_type",
        "rules[1].match.http_response",
    ),
    (replaced("tls: true", "tls: 1"), "wrong_type", "rules[1].match.tls"),
    (replaced("match:\n      banner", "match: [x]\n      banner"), "invalid_yaml", "<file>"),
    # invalid values
    ("schema_version: 2\nrules: []\n", "unsupported_version", "schema_version"),
    ("schema_version: 1\nrules: []\n", "invalid_value", "rules"),
    (replaced("id: ssh-id", "id: SSH"), "invalid_value", "rules[0].id"),
    (replaced("id: ssh-id", "id: ''"), "invalid_value", "rules[0].id"),
    (replaced("id: ssh-id", "id: " + "a" * 49), "invalid_value", "rules[0].id"),
    (replaced("service: ssh", "service: SSH"), "invalid_value", "rules[0].service"),
    (replaced("confidence: high", "confidence: certain"), "invalid_value", "rules[0].confidence"),
    (
        replaced("description: SSH identification string.", 'description: "bell\\a"'),
        "invalid_value",
        "rules[0].description",
    ),
    (
        replaced("description: SSH identification string.", 'description: "bidi\\u202e"'),
        "invalid_value",
        "rules[0].description",
    ),
    (
        replaced("description: SSH identification string.", "description: " + "x" * 201),
        "invalid_value",
        "rules[0].description",
    ),
    (replaced("tls: true", "tls: false"), "invalid_value", "rules[1].match.tls"),
    (
        replaced("http_response: true", "http_response: false"),
        "invalid_value",
        "rules[1].match.http_response",
    ),
    # an empty condition list
    (
        replaced("    match:\n      banner_regex: '^SSH-[0-9]\\.[0-9]+-'\n", "    match: {}\n"),
        "empty_match",
        "rules[0].match",
    ),
    # duplicate ids
    (replaced("id: web", "id: ssh-id"), "duplicate_id", "rules[1].id"),
    # regular expressions outside the safe subset
    (replaced("'^SSH-[0-9]\\.[0-9]+-'", "'(a+)+$'"), "unsafe_regex", "rules[0].match.banner_regex"),
    (replaced("'^nginx'", "'(a)\\1'"), "unsafe_regex", "rules[1].match.http_server_regex"),
    (replaced("'^nginx'", "''"), "unsafe_regex", "rules[1].match.http_server_regex"),
    # hostile YAML
    ("a: [", "invalid_yaml", "<file>"),
    ("a: &x 1\nb: *x\n", "invalid_yaml", "<file>"),
    ("a: !!python/object/apply:os.system ['echo']\n", "invalid_yaml", "<file>"),
    ("schema_version: 1\nschema_version: 1\nrules: []\n", "invalid_yaml", "<file>"),
    (
        replaced("    service: ssh\n", "    service: ssh\n    service: ftp\n"),
        "invalid_yaml",
        "<file>",
    ),
    ("[" * 40 + "]" * 40, "invalid_yaml", "<file>"),
]


@pytest.mark.parametrize(
    ("text", "code", "location"),
    CASES,
    ids=[f"{n}-{case[2]}-{case[1]}" for n, case in enumerate(CASES)],
)
def test_invalid_rule_files_are_refused_with_a_specific_error(
    text: str, code: str, location: str
) -> None:
    error = error_of(text)
    assert (error.code.value, error.location) == (str(code), location)
    assert str(error).startswith(f"{location}: {error.code.value}: ")


def test_an_unsafe_regex_error_carries_the_reason_and_position() -> None:
    error = error_of(replaced("'^SSH-[0-9]\\.[0-9]+-'", "'ab(c+)+d'"))
    assert error.code is RuleErrorCode.UNSAFE_REGEX
    assert "may not contain a quantifier" in error.detail
    assert "at position 2" in error.detail


def test_the_duplicate_id_error_names_the_first_use() -> None:
    assert "rules[0]" in error_of(replaced("id: web", "id: ssh-id")).detail


def test_an_unknown_key_with_hostile_characters_is_shown_sanitised() -> None:
    error = error_of(VALID + '"bad\\x1b[31mkey": 1\n')
    assert error.code is RuleErrorCode.UNKNOWN_KEY
    assert "\x1b" not in str(error)


def test_too_many_rules_are_refused() -> None:
    rules = "".join(
        f"  - id: r{n}\n    service: s\n    confidence: low\n    description: d\n"
        f"    match: {{tls: true}}\n"
        for n in range(MAX_RULES + 1)
    )
    # ids with digits only after a letter are valid; the count is what is refused
    error = error_of("schema_version: 1\nrules:\n" + rules)
    assert error.code is RuleErrorCode.TOO_MANY_RULES


def test_exactly_the_maximum_number_of_rules_is_accepted() -> None:
    rules = "".join(
        f"  - id: r{n}\n    service: s\n    confidence: low\n    description: d\n"
        f"    match: {{tls: true}}\n"
        for n in range(MAX_RULES)
    )
    assert len(parse_fingerprint_rules("schema_version: 1\nrules:\n" + rules).rules) == MAX_RULES


def test_an_oversized_document_is_refused_before_it_is_parsed() -> None:
    error = error_of("# " + "x" * MAX_RULE_FILE_BYTES + "\n" + VALID)
    assert error.code is RuleErrorCode.FILE_TOO_LARGE


# -- files on disk ---------------------------------------------------------------------------


def write(tmp_path: Path, data: bytes, name: str = "rules.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_a_rule_file_loads(tmp_path: Path) -> None:
    rules = load_fingerprint_rules(write(tmp_path, VALID.encode("utf-8")))
    assert [r.id for r in rules.rules] == ["ssh-id", "web"]


def test_a_utf8_byte_order_mark_is_accepted(tmp_path: Path) -> None:
    path = write(tmp_path, b"\xef\xbb\xbf" + VALID.encode("utf-8"))
    assert len(load_fingerprint_rules(path).rules) == 2


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"\xff\xfe\x00bad", RuleErrorCode.NOT_UTF8),
        (b"#" * (MAX_RULE_FILE_BYTES + 1), RuleErrorCode.FILE_TOO_LARGE),
        (b"schema_version: 1\nrules: []\x00\n", RuleErrorCode.INVALID_YAML),
    ],
    ids=["not-utf8", "too-large", "nul-byte"],
)
def test_unusable_files_are_refused(tmp_path: Path, data: bytes, code: RuleErrorCode) -> None:
    with pytest.raises(RuleError) as caught:
        load_fingerprint_rules(write(tmp_path, data))
    assert caught.value.code is code


def test_a_file_of_exactly_the_maximum_size_is_read_in_full(tmp_path: Path) -> None:
    padding = b"# " + b"x" * (MAX_RULE_FILE_BYTES - len(VALID) - 3) + b"\n"
    data = padding + VALID.encode("utf-8")
    assert len(data) == MAX_RULE_FILE_BYTES
    assert len(load_fingerprint_rules(write(tmp_path, data)).rules) == 2


def test_a_missing_file_and_a_directory_are_refused(tmp_path: Path) -> None:
    with pytest.raises(RuleError) as missing:
        load_fingerprint_rules(tmp_path / "nope.yaml")
    assert missing.value.code is RuleErrorCode.UNREADABLE
    with pytest.raises(RuleError) as directory:
        load_fingerprint_rules(tmp_path)
    assert directory.value.code is RuleErrorCode.NOT_A_FILE


def test_an_unreadable_file_is_reported_without_the_system_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path, VALID.encode("utf-8"))

    def refuse(self: Path, *args: object, **kwargs: object) -> object:
        raise PermissionError("secret system text")

    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(RuleError) as caught:
        load_fingerprint_rules(path)
    assert caught.value.code is RuleErrorCode.UNREADABLE
    assert "PermissionError" in caught.value.detail
    assert "secret" not in str(caught.value)


# -- the built-in rules ----------------------------------------------------------------------


def test_the_built_in_rules_are_valid_and_cached() -> None:
    rules = builtin_fingerprint_rules()
    assert len(rules.rules) >= 9
    assert builtin_fingerprint_rules() is rules
    ids = [r.id for r in rules.rules]
    assert len(set(ids)) == len(ids)
    assert {r.service for r in rules.rules} >= {"ssh", "http", "tls", "telnet"}


def test_a_missing_built_in_file_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    class Missing:
        def __truediv__(self, _: str) -> Missing:
            return self

        def read_bytes(self) -> bytes:
            raise FileNotFoundError

    monkeypatch.setattr(loader_module, "files", lambda _package: Missing())
    builtin_fingerprint_rules.cache_clear()
    try:
        with pytest.raises(RuleError) as caught:
            builtin_fingerprint_rules()
        assert caught.value.code is RuleErrorCode.UNREADABLE
    finally:
        monkeypatch.undo()
        builtin_fingerprint_rules.cache_clear()
