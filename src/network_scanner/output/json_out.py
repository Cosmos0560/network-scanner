"""JSON output: the whole report, keys in model order, ASCII only, every string sanitised."""

from __future__ import annotations

import json

from network_scanner.core.model import ScanReport
from network_scanner.output.common import jsonable


def render_json(report: ScanReport) -> str:
    return json.dumps(jsonable(report), indent=2, ensure_ascii=True) + "\n"
