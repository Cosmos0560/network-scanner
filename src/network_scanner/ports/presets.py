"""Port presets, loaded from packaged YAML (decision D3: PyYAML, `safe_load` only).

The data file is trusted no more than any other input: it is size-capped, loaded through
`core/yamlsafe.py` (an event-stream check, then `yaml.safe_load`; see there for what is
refused) and validated against a closed schema.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

from network_scanner.core.errors import NetworkScannerError
from network_scanner.core.yamlsafe import safe_load_document

PRESET_FILES: dict[str, str] = {"common": "ports_common.yaml"}
PRESET_NAMES = tuple(sorted(PRESET_FILES))
MAX_PRESET_BYTES = 64 * 1024
MAX_PRESET_PORTS = 1024
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class PresetError(NetworkScannerError):
    """A preset file is missing, malformed or does not match the schema."""


@dataclass(frozen=True, slots=True)
class PresetEntry:
    port: int
    service: str


@dataclass(frozen=True, slots=True)
class Preset:
    name: str
    description: str
    entries: tuple[PresetEntry, ...]

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(entry.port for entry in self.entries)


def _int(value: Any, what: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise PresetError(f"{what} must be an integer from {low} to {high}")
    return value


def _text(value: Any, what: str, pattern: re.Pattern[str] | None, max_chars: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_chars:
        raise PresetError(f"{what} must be a string of 1-{max_chars} characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise PresetError(f"{what} has an invalid form")
    if any(unicodedata.category(c) in _REFUSED_CATEGORIES for c in value):
        raise PresetError(f"{what} contains control characters")
    return value


def _mapping(value: Any, what: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PresetError(f"{what} must be a mapping with exactly the keys {sorted(keys)}")
    return value


def parse_preset(text: str, *, expected_name: str | None = None) -> Preset:
    """Parse and validate one preset document."""
    if len(text.encode("utf-8")) > MAX_PRESET_BYTES:
        raise PresetError(f"preset is larger than {MAX_PRESET_BYTES} bytes")
    document = safe_load_document(text, error=PresetError)
    top = _mapping(document, "the preset", {"schema_version", "name", "description", "ports"})
    _int(top["schema_version"], "schema_version", 1, 1)  # only version 1 exists
    name = _text(top["name"], "name", _NAME, 32)
    if expected_name is not None and name != expected_name:
        raise PresetError(f"preset name {name!r} does not match {expected_name!r}")
    description = _text(top["description"], "description", None, 200)
    raw_ports = top["ports"]
    if not isinstance(raw_ports, list) or not 1 <= len(raw_ports) <= MAX_PRESET_PORTS:
        raise PresetError(f"ports must be a list of 1-{MAX_PRESET_PORTS} entries")
    entries = []
    for item in raw_ports:
        entry = _mapping(item, "each port entry", {"port", "service"})
        entries.append(
            PresetEntry(
                _int(entry["port"], "port", 1, 65535),
                _text(entry["service"], "service", _SERVICE, 32),
            )
        )
    ports = [entry.port for entry in entries]
    if ports != sorted(set(ports)):
        raise PresetError("ports must be unique and in ascending order")
    return Preset(name, description, tuple(entries))


@cache
def load_preset(name: str) -> Preset:
    """Load a packaged preset by name."""
    if name not in PRESET_FILES:
        raise PresetError(f"unknown preset {name!r}")
    resource = files("network_scanner.ports") / "data" / PRESET_FILES[name]
    try:
        data = resource.read_bytes()
    except OSError:
        raise PresetError(f"preset file for {name!r} is missing") from None
    if len(data) > MAX_PRESET_BYTES:
        raise PresetError(f"preset is larger than {MAX_PRESET_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise PresetError("preset is not valid UTF-8") from None
    return parse_preset(text, expected_name=name)


def render_markdown_table(preset: Preset) -> str:
    """The preset as the Markdown table that docs/ports.md must contain."""
    lines = ["| Port | Service |", "|------|---------|"]
    lines.extend(f"| {entry.port} | {entry.service} |" for entry in preset.entries)
    return "\n".join(lines)
