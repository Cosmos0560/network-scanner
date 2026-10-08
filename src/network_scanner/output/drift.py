"""Output for `baseline diff`: the drift as a table or as JSON.

Both carry every entry (address, port, service) of the four lists, so the output is enough to
act on without the baseline file. Everything is sanitised; the table is ASCII.
"""

from __future__ import annotations

import json

from network_scanner.baseline.diff import has_drift
from network_scanner.core.model import BaselineEntry, Drift, Finding
from network_scanner.output.common import clean, jsonable, severity_counts

_UNIDENTIFIED = "unidentified"


def _entry(entry: BaselineEntry) -> str:
    return f"{clean(entry.address, max_chars=100)}:{entry.port} ({entry.service or _UNIDENTIFIED})"


def render_drift_table(drift: Drift, findings: tuple[Finding, ...] = ()) -> str:
    lines = ["baseline diff: " + ("drift found" if has_drift(drift) else "no drift")]
    lines.append(
        f"new: {len(drift.new)}  closed: {len(drift.closed)}  changed: {len(drift.changed)}  "
        f"not scanned: {len(drift.not_scanned)}"
    )
    body = [f"NEW          {_entry(entry)}" for entry in drift.new]
    body += [f"CLOSED       {_entry(entry)}" for entry in drift.closed]
    body += [
        f"CHANGED      {clean(before.address, max_chars=100)}:{before.port} "
        f"{before.service or _UNIDENTIFIED} -> {after.service or _UNIDENTIFIED}"
        for before, after in drift.changed
    ]
    body += [f"NOT SCANNED  {_entry(entry)}" for entry in drift.not_scanned]
    if body:
        lines.append("")
        lines.extend(body)
    if findings:
        lines.append("")
        total = severity_counts([finding.severity for finding in findings])
        lines.append(f"findings in this scan: {len(findings)} ({total})")
        for finding in sorted(findings, key=lambda f: -f.severity.rank):
            lines.append(
                f"  [{finding.severity.value}/{finding.confidence.value}] {clean(finding.id)} "
                f"{clean(finding.address, max_chars=100)}:{finding.port}"
            )
    return "\n".join(lines) + "\n"


def render_drift_json(drift: Drift, findings: tuple[Finding, ...] = ()) -> str:
    document = {
        "has_drift": has_drift(drift),
        "drift": jsonable(drift),
        "findings": jsonable(findings),
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"
