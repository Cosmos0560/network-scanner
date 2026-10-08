"""CSV output, safe to open in a spreadsheet.

One header row, then one `port` row per probed port (with the service and TLS facts of an
inspected open port) and one `finding` row per finding, in the same columns. Every string is
sanitised, and every string cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return
gets a leading apostrophe, so a spreadsheet shows it as text instead of running it as a formula
(OWASP "CSV injection"). Numbers are written unquoted and are never negative, so they need
no such treatment. Booleans are `true` and `false`, and unknown is an empty cell.
"""

from __future__ import annotations

import csv
import io

from network_scanner.core.model import PortObservation, ScanReport, TlsInfo
from network_scanner.output.common import clean

FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")

COLUMNS = (
    "record",
    "address",
    "port",
    "state",
    "error_code",
    "service",
    "service_confidence",
    "service_rule",
    "probe",
    "banner",
    "banner_truncated",
    "http_status",
    "http_server",
    "tls_version",
    "tls_cipher",
    "tls_subject",
    "tls_issuer",
    "tls_not_before",
    "tls_not_after",
    "tls_san",
    "tls_self_issued",
    "tls_self_signature_valid",
    "tls_expired",
    "tls_hostname_match",
    "tls_sha256",
    "tls_parse_error",
    "finding_id",
    "severity",
    "confidence",
    "title",
    "evidence",
    "references",
)

Cell = str | int | None


def neutralise(text: str) -> str:
    """Sanitise `text` and defuse a leading formula character.

    The check looks at the raw text and at the sanitised text with its leading spaces removed,
    because the sanitiser turns a leading tab or carriage return into a space, and some
    spreadsheets trim spaces before they decide whether a cell is a formula.
    """
    cleaned = clean(text)
    risky = text.startswith(FORMULA_STARTS) or cleaned.lstrip(" ").startswith(FORMULA_STARTS)
    return "'" + cleaned if risky else cleaned


def _boolean(value: bool | None) -> str:
    return "" if value is None else ("true" if value else "false")


def _tls_cells(tls: TlsInfo | None) -> dict[str, Cell]:
    if tls is None:
        return {}
    return {
        "tls_version": tls.version,
        "tls_cipher": tls.cipher,
        "tls_subject": tls.subject,
        "tls_issuer": tls.issuer,
        "tls_not_before": tls.not_before,
        "tls_not_after": tls.not_after,
        "tls_san": "; ".join(tls.san) + ("; ..." if tls.san_truncated else ""),
        "tls_self_issued": _boolean(tls.self_issued),
        "tls_self_signature_valid": _boolean(tls.self_signature_valid),
        "tls_expired": _boolean(tls.expired),
        "tls_hostname_match": _boolean(tls.hostname_match),
        "tls_sha256": tls.sha256,
        "tls_parse_error": tls.parse_error,
    }


def _observation_cells(found: PortObservation | None) -> dict[str, Cell]:
    if found is None:
        return {}
    seen = found.observation
    cells: dict[str, Cell] = {
        "probe": seen.probe,
        "banner": seen.banner,
        "banner_truncated": _boolean(seen.banner_truncated),
        "http_status": seen.http_status,
        "http_server": seen.http_server,
    }
    if found.service is not None:
        cells.update(
            service=found.service.name,
            service_confidence=found.service.confidence.value,
            service_rule=found.service.rule_id,
        )
    return {**cells, **_tls_cells(seen.tls)}


def _cell(value: Cell) -> str | int:
    if value is None:
        return ""
    return value if isinstance(value, int) else neutralise(value)


def render_csv(report: ScanReport) -> str:
    inspected = {(found.address, found.port): found for found in report.observations}
    rows: list[dict[str, Cell]] = []
    for result in report.results:
        row: dict[str, Cell] = {
            "record": "port",
            "address": result.address,
            "port": result.port,
            "state": result.state.value,
            "error_code": None if result.error_code is None else result.error_code.value,
        }
        row.update(_observation_cells(inspected.get((result.address, result.port))))
        rows.append(row)
    for finding in report.findings:
        rows.append(
            {
                "record": "finding",
                "address": finding.address,
                "port": finding.port,
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "title": finding.title,
                "evidence": finding.evidence,
                "references": "; ".join(finding.references),
            }
        )
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_NONNUMERIC)
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in COLUMNS])
    return buffer.getvalue()
