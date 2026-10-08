"""Plain-text table output. ASCII only, so every console code page can show it.

The port table lists open, filtered and error results; closed ports are only counted. When the
scan inspected its open ports (`report.probed`) the table gains a SERVICE column, then a block
of details per inspected port (banner, HTTP answer, TLS and certificate facts), then the
findings, most severe first, each with its evidence and references. Everything that reaches the
screen passes through the sanitiser, even values that are safe by construction.
"""

from __future__ import annotations

from collections import Counter

from network_scanner.core.model import Finding, PortObservation, PortState, ScanReport
from network_scanner.output.common import clean, severity_counts

_NAME_CHARS = 300
_NONE = "-"


def _clean(text: str) -> str:
    return clean(text, max_chars=_NAME_CHARS)


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _service_cell(found: PortObservation | None) -> str:
    if found is None or found.service is None:
        return _NONE
    return f"{_clean(found.service.name)} ({found.service.confidence.value})"


def _detail_lines(found: PortObservation) -> list[str]:
    seen = found.observation
    lines: list[str] = []
    if seen.banner is not None:
        cut = " (cut)" if seen.banner_truncated else ""
        lines.append(f"  banner: {_clean(seen.banner)}{cut}")
    if seen.http_status is not None:
        server = _clean(seen.http_server) if seen.http_server else _NONE
        lines.append(f"  http: status {seen.http_status}, server {server}")
    tls = seen.tls
    if tls is not None:
        lines.append(f"  tls: {_clean(tls.version or _NONE)}, cipher {_clean(tls.cipher or _NONE)}")
        if tls.parse_error is not None:
            lines.append(f"  certificate not read: {_clean(tls.parse_error)}")
        else:
            lines.append(
                f"  certificate: subject {_clean(tls.subject or _NONE)}; "
                f"issuer {_clean(tls.issuer or _NONE)}"
            )
            start, end = _clean(tls.not_before or _NONE), _clean(tls.not_after or _NONE)
            lines.append(f"  validity: {start} to {end}; expired {_yes_no(tls.expired)}")
            names = ", ".join(tls.san) + (", ..." if tls.san_truncated else "")
            lines.append(f"  names: {_clean(names) if names else _NONE}")
            lines.append(
                f"  facts: self-issued {_yes_no(tls.self_issued)}; "
                f"signature verifies under own key {_yes_no(tls.self_signature_valid)}; "
                f"host name matches {_yes_no(tls.hostname_match)}"
            )
        lines.append(f"  sha256: {_clean(tls.sha256 or _NONE)}")
    return lines


def _finding_lines(finding: Finding) -> list[str]:
    lines = [
        f"[{finding.severity.value}/{finding.confidence.value}] {_clean(finding.id)} "
        f"{_clean(finding.address)}:{finding.port} - {_clean(finding.title)}",
        f"    evidence: {_clean(finding.evidence)}",
    ]
    if finding.references:
        lines.append(f"    references: {_clean(', '.join(finding.references))}")
    return lines


def render_table(report: ScanReport) -> str:
    names = {target.address: target.display_name for target in report.targets}
    counts = Counter(result.state for result in report.results)
    inspected = {(found.address, found.port): found for found in report.observations}

    lines = [
        f"network-scanner {_clean(report.tool_version)}  started {_clean(report.started_at)}",
        f"targets: {len(report.targets)}  probes completed: {len(report.results)}",
    ]
    if not report.complete:
        lines.append("INCOMPLETE: the scan stopped before every probe finished")
    lines.append("")

    rows = []
    for result in report.results:
        if result.state is PortState.CLOSED:
            continue
        address = (
            result.address
            if names.get(result.address, result.address) == result.address
            else f"{names[result.address]} ({result.address})"
        )
        row = [
            _clean(address),
            str(result.port),
            result.state.value + (f" ({result.error_code.value})" if result.error_code else ""),
        ]
        if report.probed:
            row.append(_service_cell(inspected.get((result.address, result.port))))
        rows.append(row)
    if rows:
        header = ["ADDRESS", "PORT", "STATE", *(["SERVICE"] if report.probed else [])]
        table = [header, *rows]
        widths = [max(len(row[i]) for row in table) for i in range(len(header))]
        for row in table:
            cells = [
                f"{row[0]:<{widths[0]}}",
                f"{row[1]:>{widths[1]}}",
                *(f"{cell:<{widths[i]}}" for i, cell in enumerate(row[2:], start=2)),
            ]
            lines.append("  ".join(cells).rstrip())
    else:
        lines.append("no open, filtered or error results")

    details = [(found, _detail_lines(found)) for found in report.observations]
    details = [(found, text) for found, text in details if text]
    if details:
        lines.append("")
        lines.append("PORT DETAILS")
        for found, text in details:
            lines.append(f"{_clean(found.address)}:{found.port}")
            lines.extend(text)

    if report.findings:
        lines.append("")
        lines.append("FINDINGS")
        for finding in sorted(report.findings, key=lambda f: -f.severity.rank):
            lines.extend(_finding_lines(finding))

    lines.append("")
    lines.append(
        "open: {}  closed: {}  filtered: {}  error: {}".format(
            *(counts[state] for state in PortState)
        )
    )
    if report.probed:
        total = severity_counts([finding.severity for finding in report.findings])
        lines.append(f"findings: {len(report.findings)}" + (f" ({total})" if total else ""))
    return "\n".join(lines) + "\n"
