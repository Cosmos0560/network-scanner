"""The baseline file: the open ports and services seen by one complete, fingerprinted scan.

A baseline is read back later, so it is untrusted input: the file may have been edited, truncated
or replaced. Reading is strict. The size is capped before anything is parsed; the JSON must have
exactly the keys `schema_version`, `kind`, `created_at` and `entries`; no duplicate keys, no
floats and no NaN; the version must be known (a newer one is refused with a clear message);
every entry has exactly `address` (an IP literal, in any spelling `parse_ip` accepts, stored in
canonical form), `port` (1-65535) and `service` (null or a service-name token); and no
(address, port) appears twice. Anything else is a `BaselineError` (exit code 2) that says where.

A baseline is written from a scan that is complete and was fingerprinted, because a partial
scan would turn every port it missed into "closed" and an unfingerprinted one would turn every
service into "changed". Entries are sorted, and `created_at` is the scan's start time from the
injected clock, so the same scan always gives the same file.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from network_scanner.core.errors import ScopeRefusal, UsageError
from network_scanner.core.limits import MAX_BASELINE_BYTES, MAX_BASELINE_ENTRIES
from network_scanner.core.model import (
    SCHEMA_VERSION,
    Baseline,
    BaselineEntry,
    PortState,
    ScanReport,
    to_jsonable,
)
from network_scanner.core.sanitize import sanitize_text
from network_scanner.scope.parser import parse_ip

BASELINE_KIND = "network-scanner-baseline"
BASELINE_SCHEMA_VERSION = SCHEMA_VERSION
_TOP_KEYS = ("schema_version", "kind", "created_at", "entries")
_ENTRY_KEYS = ("address", "port", "service")
_CREATED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,15}(?:Z|[+-][0-9]{2}:[0-9]{2})")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


class BaselineError(UsageError):
    """A baseline cannot be written from this scan, or the file read back is not acceptable."""


def _shown(value: object) -> str:
    return repr(sanitize_text(str(value), max_chars=40).text)


def sort_key(entry: BaselineEntry) -> tuple[int, int, str, int]:
    address = parse_ip(entry.address)
    return (*address.sort_key(), entry.port)


def build_baseline(report: ScanReport) -> Baseline:
    """The baseline for a complete, fingerprinted scan report."""
    if not report.complete:
        raise BaselineError("the scan was not complete, so it cannot be a baseline")
    if not report.probed:
        raise BaselineError("the scan was connect-only; a baseline needs fingerprinted services")
    services = {
        (found.address, found.port): None if found.service is None else found.service.name
        for found in report.observations
    }
    entries = [
        BaselineEntry(result.address, result.port, services.get((result.address, result.port)))
        for result in report.results
        if result.state is PortState.OPEN
    ]
    entries.sort(key=sort_key)
    return Baseline(BASELINE_SCHEMA_VERSION, report.started_at, tuple(entries))


def render_baseline(baseline: Baseline) -> str:
    document: dict[str, Any] = {
        "schema_version": baseline.schema_version,
        "kind": BASELINE_KIND,
        "created_at": baseline.created_at,
        "entries": to_jsonable(baseline.entries),
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


# -- reading ---------------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise BaselineError("a JSON object has a duplicate key")
    return dict(pairs)


def _refuse_constant(name: str) -> Any:
    raise BaselineError(f"the JSON constant {name} is not accepted")


def _refuse_float(text: str) -> Any:
    raise BaselineError("numbers with a fractional part or an exponent are not accepted")


def _object(value: Any, location: str, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BaselineError(f"{location}: expected an object")
    for key in value:
        if key not in keys:
            raise BaselineError(f"{location}: unknown key {_shown(key)}")
    for key in keys:
        if key not in value:
            raise BaselineError(f"{location}: missing key {key!r}")
    return value


def _entry(raw: Any, location: str) -> BaselineEntry:
    entry = _object(raw, location, _ENTRY_KEYS)
    address = entry["address"]
    if not isinstance(address, str) or len(address) > 64:
        raise BaselineError(f"{location}.address: expected an IP address string")
    try:
        canonical = parse_ip(address).text
    except ScopeRefusal as refusal:
        raise BaselineError(f"{location}.address: {refusal.reason_code.value}") from None
    port = entry["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BaselineError(f"{location}.port: expected a whole number from 1 to 65535")
    service = entry["service"]
    if service is not None and (not isinstance(service, str) or not _SERVICE.fullmatch(service)):
        raise BaselineError(f"{location}.service: expected null or a service name")
    return BaselineEntry(canonical, port, service)


def parse_baseline(data: bytes) -> Baseline:
    """Validate the bytes of a baseline file."""
    if len(data) > MAX_BASELINE_BYTES:
        raise BaselineError(f"the baseline is larger than {MAX_BASELINE_BYTES} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise BaselineError("the baseline is not valid UTF-8") from None
    try:
        document = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_refuse_constant,
            parse_float=_refuse_float,
        )
    except json.JSONDecodeError as exc:
        raise BaselineError(f"the baseline is not valid JSON (line {exc.lineno})") from None
    except RecursionError:
        raise BaselineError("the baseline is nested too deeply") from None

    top = _object(document, "baseline", _TOP_KEYS)
    version = top["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise BaselineError("schema_version: expected a whole number")
    if version > BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"schema_version {version} was written by a newer network-scanner; "
            f"this one reads version {BASELINE_SCHEMA_VERSION}"
        )
    if version != BASELINE_SCHEMA_VERSION:
        raise BaselineError(f"schema_version {version} is not supported")
    if top["kind"] != BASELINE_KIND:
        raise BaselineError(f"kind: expected {BASELINE_KIND!r}; this is not a baseline file")
    created = top["created_at"]
    if not isinstance(created, str) or _CREATED.fullmatch(created) is None:
        raise BaselineError("created_at: expected an ISO 8601 time")
    raw_entries = top["entries"]
    if not isinstance(raw_entries, list):
        raise BaselineError("entries: expected a list")
    if len(raw_entries) > MAX_BASELINE_ENTRIES:
        raise BaselineError(f"entries: more than {MAX_BASELINE_ENTRIES} entries")

    entries: list[BaselineEntry] = []
    seen: dict[tuple[str, int], int] = {}
    for index, raw in enumerate(raw_entries):
        entry = _entry(raw, f"entries[{index}]")
        key = (entry.address, entry.port)
        if key in seen:
            raise BaselineError(
                f"entries[{index}]: the same address and port as entries[{seen[key]}]"
            )
        seen[key] = index
        entries.append(entry)
    entries.sort(key=sort_key)
    return Baseline(version, created, tuple(entries))


def load_baseline(path: Path) -> Baseline:
    """Read a baseline file: a regular file only, at most the size cap plus one byte."""
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise BaselineError("the baseline path is not a regular file")
        with path.open("rb") as handle:
            data = handle.read(MAX_BASELINE_BYTES + 1)
    except OSError as exc:
        raise BaselineError(f"cannot read the baseline file ({type(exc).__name__})") from None
    return parse_baseline(data)
