"""JSON output: the whole report, keys in model order, ASCII only."""

from __future__ import annotations

import json

from network_scanner.core.model import ScanReport, to_jsonable


def render_json(report: ScanReport) -> str:
    return json.dumps(to_jsonable(report), indent=2, ensure_ascii=True) + "\n"
