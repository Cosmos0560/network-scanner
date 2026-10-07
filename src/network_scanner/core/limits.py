"""Default limits and hard ceilings (PLAN.md section 4.6).

Ceilings are module constants. A `Limits` value can be lowered or raised up to its
ceiling, never past it, and every field must be positive.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from network_scanner.core.errors import LimitError


@dataclass(frozen=True, slots=True)
class Limits:
    """Per-run limits. Defaults match PLAN.md section 4.6."""

    max_targets: int = 256
    max_ports_per_target: int = 1024
    concurrency: int = 64
    connections_per_second: int = 100
    connect_timeout_s: float = 3.0
    banner_timeout_s: float = 2.0
    banner_max_bytes: int = 1024
    total_timeout_s: float = 300.0
    probes_per_open_port: int = 3

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            ceiling = CEILINGS[field.name]
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise LimitError(f"{field.name} must be a number")
            if not 0 < value <= ceiling:
                raise LimitError(f"{field.name} must be greater than 0 and at most {ceiling}")


CEILINGS: dict[str, int | float] = {
    "max_targets": 4096,
    "max_ports_per_target": 65535,
    "concurrency": 512,
    "connections_per_second": 1000,
    "connect_timeout_s": 30.0,
    "banner_timeout_s": 10.0,
    "banner_max_bytes": 4096,
    "total_timeout_s": 3600.0,
    "probes_per_open_port": 3,
}

DEFAULT_LIMITS = Limits()
