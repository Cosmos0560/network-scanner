from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from network_scanner.ports import presets
from network_scanner.ports.presets import (
    MAX_PRESET_BYTES,
    PRESET_NAMES,
    PresetError,
    load_preset,
    parse_preset,
    render_markdown_table,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "network_scanner"

VALID = """\
schema_version: 1
name: tiny
description: A tiny preset.
ports:
  - {port: 22, service: ssh}
  - {port: 80, service: http}
"""


def error_of(text: str, **kwargs: str) -> PresetError:
    with pytest.raises(PresetError) as caught:
        parse_preset(text, **kwargs)
    return caught.value


# -- the shipped preset ---------------------------------------------------------------------


def test_the_common_preset_loads_and_is_well_formed() -> None:
    preset = load_preset("common")
    assert PRESET_NAMES == ("common",)
    assert preset.name == "common"
    assert len(preset.entries) >= 30
    assert preset.ports == tuple(sorted(set(preset.ports)))
    assert all(1 <= port <= 65535 for port in preset.ports)
    assert all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", e.service) for e in preset.entries)
    assert {22, 80, 443, 445, 3389} <= set(preset.ports)
    assert load_preset("common") is preset  # cached


def test_the_preset_says_it_is_curated_and_not_ranked() -> None:
    preset = load_preset("common")
    assert "not ranked" in preset.description.lower()
    data = (SRC / "ports" / "data" / "ports_common.yaml").read_text(encoding="utf-8")
    assert "curated" in data.lower()
    assert "NOT ranked" in data


def test_an_unknown_preset_is_an_error() -> None:
    with pytest.raises(PresetError, match="unknown preset"):
        load_preset("top100")


def test_the_markdown_table_has_one_row_per_entry() -> None:
    preset = load_preset("common")
    lines = render_markdown_table(preset).splitlines()
    assert lines[:2] == ["| Port | Service |", "|------|---------|"]
    assert lines[2] == "| 21 | ftp |"
    assert len(lines) == 2 + len(preset.entries)


# -- parsing and validation -------------------------------------------------------------------


def test_a_minimal_document_parses() -> None:
    preset = parse_preset(VALID, expected_name="tiny")
    assert (preset.name, preset.ports) == ("tiny", (22, 80))
    assert preset.entries[0].service == "ssh"


def test_the_expected_name_must_match() -> None:
    assert "does not match" in str(error_of(VALID, expected_name="other"))


@pytest.mark.parametrize(
    ("document", "fragment"),
    [
        ("a: [", "invalid YAML"),
        ("- 1\n- 2\n", "mapping"),
        ("just text", "mapping"),
        ("", "mapping"),
        ("a: 1\n---\nb: 2\n", "invalid YAML"),
        ("? [a, b]\n: c\n", "plain scalars"),
        ("&anchor x: 1\n", "anchors"),
        ("a: &x 1\nb: *x\n", "anchors"),
        ("a: *x\n", "aliases"),
        ("a: !!str 1\n", "explicit tags"),
        ("a: !!python/object/apply:os.system ['echo hacked']\n", "explicit tags"),
        ("!!python/name:os.system\n", "explicit tags"),
        ("a: 1\na: 2\n", "duplicate key"),
        (VALID.replace("name: tiny\n", "name: tiny\nname: tiny\n"), "duplicate key"),
        (
            VALID.replace("{port: 22, service: ssh}", "{port: 22, port: 23, service: ssh}"),
            "duplicate",
        ),
        ("[" * 40 + "]" * 40, "nested too deeply"),
        ("a: " + "{b: " * 20 + "1" + "}" * 20, "nested too deeply"),
        (VALID + "extra: 1\n", "exactly the keys"),
        (VALID.replace("description: A tiny preset.\n", ""), "exactly the keys"),
        (VALID.replace("schema_version: 1", "schema_version: 2"), "schema_version"),
        (VALID.replace("schema_version: 1", 'schema_version: "1"'), "schema_version"),
        (VALID.replace("schema_version: 1", "schema_version: true"), "schema_version"),
        (VALID.replace("name: tiny", "name: Tiny"), "name"),
        (VALID.replace("name: tiny", "name: 1"), "name"),
        (VALID.replace("description: A tiny preset.", "description: ''"), "description"),
        (VALID.replace("description: A tiny preset.", f"description: {'x' * 201}"), "description"),
        (VALID.replace("description: A tiny preset.", 'description: "bell\\a"'), "control"),
        (VALID.replace("description: A tiny preset.", 'description: "bidi\\u202e"'), "control"),
        (VALID.replace("{port: 22, service: ssh}", "{port: 22}"), "exactly the keys"),
        (VALID.replace("{port: 22, service: ssh}", "{port: 22, service: ssh, x: 1}"), "exactly"),
        (VALID.replace("{port: 22, service: ssh}", "22"), "mapping"),
        (VALID.replace("port: 22,", "port: 0,"), "port must be"),
        (VALID.replace("port: 22,", "port: 65536,"), "port must be"),
        (VALID.replace("port: 22,", 'port: "22",'), "port must be"),
        (VALID.replace("port: 22,", "port: 22.5,"), "port must be"),
        (VALID.replace("port: 22,", "port: true,"), "port must be"),
        (VALID.replace("service: ssh", "service: SSH"), "service"),
        (VALID.replace("service: ssh", "service: ''"), "service"),
        (VALID.replace("service: ssh", "service: -ssh"), "service"),
        (VALID.replace("service: ssh", f"service: {'a' * 33}"), "service"),
        (VALID.replace("service: ssh", "service: 22"), "service"),
        (VALID.replace("port: 80,", "port: 22,"), "unique and in ascending order"),
        (VALID.replace("port: 22,", "port: 90,"), "unique and in ascending order"),
        ("schema_version: 1\nname: tiny\ndescription: d\nports: []\n", "ports must be a list"),
        ("schema_version: 1\nname: tiny\ndescription: d\nports: nope\n", "ports must be a list"),
    ],
    ids=lambda v: repr(v)[:50],
)
def test_hostile_or_malformed_documents_are_refused(document: str, fragment: str) -> None:
    assert fragment in str(error_of(document))


def test_too_many_entries_are_refused() -> None:
    rows = "\n".join(f"  - {{port: {n}, service: s}}" for n in range(1, 1026))
    document = f"schema_version: 1\nname: big\ndescription: d\nports:\n{rows}\n"
    assert "ports must be a list of 1-1024" in str(error_of(document))


def test_a_billion_laughs_document_is_refused_before_anything_expands() -> None:
    levels = ["a: &a0 [x, x, x, x, x, x, x, x, x]"]
    levels += [f"b{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 9) + "]" for i in range(1, 12)]
    document = "\n".join(levels) + "\n"
    assert "aliases" in str(error_of(document)) or "anchors" in str(error_of(document))


def test_the_size_cap_applies_to_the_text() -> None:
    padding = "# " + "x" * MAX_PRESET_BYTES + "\n"
    assert "larger than" in str(error_of(padding + VALID))


# -- loading from package data ----------------------------------------------------------------


class FakeResource:
    def __init__(self, data: bytes | OSError) -> None:
        self.data = data

    def __truediv__(self, _: str) -> FakeResource:
        return self

    def read_bytes(self) -> bytes:
        if isinstance(self.data, OSError):
            raise self.data
        return self.data


def install(monkeypatch: pytest.MonkeyPatch, name: str, data: bytes | OSError) -> None:
    monkeypatch.setitem(presets.PRESET_FILES, name, f"{name}.yaml")
    monkeypatch.setattr(presets, "files", lambda _package: FakeResource(data))
    presets.load_preset.cache_clear()


def test_loading_reports_a_missing_oversized_or_non_utf8_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        install(monkeypatch, "ghost", FileNotFoundError())
        with pytest.raises(PresetError, match="missing"):
            load_preset("ghost")
        install(monkeypatch, "ghost", b"#" * (MAX_PRESET_BYTES + 1))
        with pytest.raises(PresetError, match="larger than"):
            load_preset("ghost")
        install(monkeypatch, "ghost", b"\xff\xfe\x00")
        with pytest.raises(PresetError, match="UTF-8"):
            load_preset("ghost")
        install(monkeypatch, "ghost", VALID.replace("tiny", "ghost").encode("utf-8"))
        assert load_preset("ghost").ports == (22, 80)
    finally:
        monkeypatch.undo()
        presets.load_preset.cache_clear()


# -- decision D3: safe_load only --------------------------------------------------------------


def test_no_source_file_uses_an_unsafe_yaml_loader() -> None:
    unsafe = {"load", "load_all", "full_load", "full_load_all", "unsafe_load", "unsafe_load_all"}
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "yaml"
                and node.attr in unsafe
            ):
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and node.module == "yaml":
                offenders.extend(
                    f"{path.relative_to(SRC).as_posix()}:{node.lineno}"
                    for alias in node.names
                    if alias.name in unsafe
                )
    assert offenders == []
    assert "yaml.safe_load(" in (SRC / "ports" / "presets.py").read_text(encoding="utf-8")
