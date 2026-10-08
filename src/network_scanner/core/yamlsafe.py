"""One safe way to load YAML data files (decision D3: PyYAML, `safe_load` only).

The text is first scanned as an event stream, without building any objects, and refused if it
uses a feature that has no place in a data file: aliases and anchors (a small file could
expand into a huge one), explicit tags, duplicate keys, non-scalar keys and deep nesting.
Only then does `yaml.safe_load` build the document. Callers cap the size of the text first
and validate the result against their own closed schema.

Failures are reported through the `error` callable the caller passes in, so each caller
raises its own error type with its own wording prefix.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import yaml

MAX_YAML_DEPTH = 8


@dataclass(slots=True)
class _Frame:
    is_mapping: bool
    keys: set[str]
    expecting_key: bool = True


def _scan_events(text: str, error: Callable[[str], Exception]) -> None:
    frames: list[_Frame] = []
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise error("YAML aliases are not allowed")
        if isinstance(event, yaml.SequenceEndEvent | yaml.MappingEndEvent):
            frames.pop()
            continue
        if not isinstance(
            event, yaml.ScalarEvent | yaml.SequenceStartEvent | yaml.MappingStartEvent
        ):
            continue
        if event.anchor is not None or event.tag is not None:
            raise error("YAML anchors and explicit tags are not allowed")
        if frames and frames[-1].is_mapping:
            frame = frames[-1]
            if frame.expecting_key:
                if not isinstance(event, yaml.ScalarEvent):
                    raise error("mapping keys must be plain scalars")
                if event.value in frame.keys:
                    raise error(f"duplicate key {event.value!r}")
                frame.keys.add(event.value)
            frame.expecting_key = not frame.expecting_key
        if not isinstance(event, yaml.ScalarEvent):
            if len(frames) >= MAX_YAML_DEPTH:
                raise error("YAML is nested too deeply")
            frames.append(_Frame(isinstance(event, yaml.MappingStartEvent), set()))


def safe_load_document(text: str, *, error: Callable[[str], Exception]) -> Any:
    """Scan `text` for forbidden YAML features, then load it with `yaml.safe_load`."""
    try:
        _scan_events(text, error)
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise error(f"invalid YAML ({type(exc).__name__})") from None
