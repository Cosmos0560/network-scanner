"""Plain-text table output. ASCII only, so every console code page can show it.

Open, filtered and error results are listed; closed ports are only counted. Everything that
reaches the screen passes through the sanitiser, even values that are safe by construction.
"""

from __future__ import annotations

from collections import Counter

from network_scanner.core.model import PortState, ScanReport
from network_scanner.core.sanitize import sanitize_text

_NAME_CHARS = 300


def _clean(text: str) -> str:
    return sanitize_text(text, max_chars=_NAME_CHARS).text


def render_table(report: ScanReport) -> str:
    names = {target.address: target.display_name for target in report.targets}
    counts = Counter(result.state for result in report.results)

    lines = [
        f"network-scanner {_clean(report.tool_version)}  started {_clean(report.started_at)}",
        f"targets: {len(report.targets)}  probes completed: {len(report.results)}",
    ]
    if not report.complete:
        lines.append("INCOMPLETE: the scan stopped before every probe finished")
    lines.append("")

    rows = [
        (
            _clean(
                result.address
                if names.get(result.address, result.address) == result.address
                else f"{names[result.address]} ({result.address})"
            ),
            str(result.port),
            result.state.value + (f" ({result.error_code.value})" if result.error_code else ""),
        )
        for result in report.results
        if result.state is not PortState.CLOSED
    ]
    if rows:
        header = ("ADDRESS", "PORT", "STATE")
        widths = [max(len(row[i]) for row in [header, *rows]) for i in range(3)]
        for row in [header, *rows]:
            lines.append(f"{row[0]:<{widths[0]}}  {row[1]:>{widths[1]}}  {row[2]}".rstrip())
    else:
        lines.append("no open, filtered or error results")
    lines.append("")
    lines.append(
        "open: {}  closed: {}  filtered: {}  error: {}".format(
            *(counts[state] for state in PortState)
        )
    )
    return "\n".join(lines) + "\n"
