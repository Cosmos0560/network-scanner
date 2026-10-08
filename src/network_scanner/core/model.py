"""Frozen data model (PLAN.md section 3). Everything here is JSON-serialisable.

Timestamps are ISO 8601 UTC strings produced from the injected clock; there is no
duration or round-trip-time field on purpose (non-deterministic).
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import Any

from network_scanner.core.errors import NetErrorCode, ReasonCode
from network_scanner.core.limits import Limits

SCHEMA_VERSION = 1


class TargetKind(StrEnum):
    IP = "ip"
    CIDR = "cidr"
    RANGE = "range"
    HOSTNAME = "hostname"


class Family(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class AddressClass(StrEnum):
    """Address classes from PLAN.md section 4.2."""

    LOOPBACK = "loopback"
    PRIVATE = "private"  # RFC 1918
    UNIQUE_LOCAL = "unique_local"  # fc00::/7
    LINK_LOCAL_V6 = "link_local_v6"  # fe80::/10
    PUBLIC = "public"  # everything else, including 100.64.0.0/10
    UNSPECIFIED = "unspecified"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    RESERVED = "reserved"
    LINK_LOCAL_V4 = "link_local_v4"  # 169.254.0.0/16, always refused
    DOCUMENTATION = "documentation"
    BENCHMARK = "benchmark"
    EMBEDDED_IPV4 = "embedded_ipv4"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class TargetSpec:
    raw: str
    kind: TargetKind


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    display_name: str
    address: str
    family: Family
    origin_spec: TargetSpec


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    address_class: AddressClass
    reason_code: ReasonCode | None


@dataclass(frozen=True, slots=True)
class PortResult:
    address: str
    port: int
    state: PortState
    error_code: NetErrorCode | None


@dataclass(frozen=True, slots=True)
class TlsInfo:
    """Certificate and handshake facts. `self_issued` (issuer equals subject) and
    `self_signature_valid` (signature verifies against the certificate's own key) are
    two separate facts (decision D6)."""

    version: str | None
    cipher: str | None
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    san: tuple[str, ...]  # "DNS:name" and "IP:address" entries
    san_truncated: bool  # more entries existed than `MAX_SAN_ENTRIES`
    sha256: str | None
    self_issued: bool | None
    self_signature_valid: bool | None
    expired: bool | None
    hostname_match: bool | None
    parse_error: str | None


@dataclass(frozen=True, slots=True)
class Observation:
    banner: str | None
    banner_truncated: bool
    probe: str | None
    http_status: int | None
    http_server: str | None
    tls: TlsInfo | None


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    rule_id: str
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    address: str
    port: int
    evidence: str
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: int
    tool_version: str
    started_at: str
    complete: bool
    limits: Limits
    targets: tuple[ResolvedTarget, ...]
    results: tuple[PortResult, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    address: str
    port: int
    service: str | None


@dataclass(frozen=True, slots=True)
class Baseline:
    """Entries are keyed by (address, port)."""

    schema_version: int
    created_at: str
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class Drift:
    new: tuple[BaselineEntry, ...]
    closed: tuple[BaselineEntry, ...]
    changed: tuple[tuple[BaselineEntry, BaselineEntry], ...]  # (before, after)


def to_jsonable(value: Any) -> Any:
    """Convert model values into plain JSON types (dict, list, str, int, float, bool, None).

    Dataclasses become dicts in field order, enums become their string value and tuples
    become lists. Anything else is rejected rather than guessed at.
    """
    if value is None or isinstance(value, bool | int | float | str):
        # StrEnum members are str instances; normalise them to the plain value.
        return value.value if isinstance(value, StrEnum) else value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, tuple | list):
        return [to_jsonable(item) for item in value]
    raise TypeError(f"cannot serialise {type(value).__name__}")
