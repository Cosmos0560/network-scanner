"""JSON Lines output: one compact JSON object per line, each with a `type` first.

Lines, in order: one `scan` (the report's metadata and limits), then one `target` per scanned
target, one `result` per probed port, one `observation` per inspected open port (with the
service its fingerprint matched, or null) and one `finding` per finding. A consumer can stream
it and pick the types it needs. Every string is sanitised, the output is ASCII, and a line never
contains a raw line break, because JSON escapes them.
"""

from __future__ import annotations

import json
from typing import Any

from network_scanner.core.model import ScanReport
from network_scanner.output.common import jsonable


def _line(kind: str, payload: dict[str, Any]) -> str:
    return json.dumps({"type": kind, **payload}, ensure_ascii=True, separators=(",", ":"))


def render_jsonl(report: ScanReport) -> str:
    data = jsonable(report)
    lines = [
        _line(
            "scan",
            {
                key: data[key]
                for key in (
                    "schema_version",
                    "tool_version",
                    "started_at",
                    "complete",
                    "probed",
                    "limits",
                )
            },
        )
    ]
    lines.extend(_line("target", target) for target in data["targets"])
    lines.extend(_line("result", result) for result in data["results"])
    lines.extend(_line("observation", found) for found in data["observations"])
    lines.extend(_line("finding", finding) for finding in data["findings"])
    return "\n".join(lines) + "\n"
