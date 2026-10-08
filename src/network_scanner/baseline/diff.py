"""Compare a saved baseline with the current scan: what is new, closed, changed or not covered.

Entries are matched by (address, port). Only the service name is compared, so the time of the
scan (`created_at`) and everything else about a port are ignored. Reading the result:

- new: open now, not in the baseline;
- closed: in the baseline, probed by this scan, and not open now (closed, filtered or error);
- changed: open in both with a different service name (including known versus unidentified);
- not scanned: in the baseline but not probed by this scan (a narrower target or port list),
  which is reported so that it cannot be mistaken for "unchanged" but is not drift.

Drift (the first three) is what makes `baseline diff` exit with code 1.
"""

from __future__ import annotations

from collections.abc import Collection

from network_scanner.baseline.store import sort_key
from network_scanner.core.model import Baseline, Drift
from network_scanner.scope.parser import parse_ip

Key = tuple[int, int, str, int]


def entry_key(address: str, port: int) -> Key:
    return (*parse_ip(address).sort_key(), port)


def diff_baselines(before: Baseline, now: Baseline, probed: Collection[tuple[str, int]]) -> Drift:
    """`probed` is every (address, port) the current scan tried, whatever it found."""
    probed_keys = {entry_key(address, port) for address, port in probed}
    old = {entry_key(e.address, e.port): e for e in before.entries}
    new = {entry_key(e.address, e.port): e for e in now.entries}

    appeared = [new[key] for key in new if key not in old]
    closed = [old[key] for key in old if key not in new and key in probed_keys]
    skipped = [old[key] for key in old if key not in new and key not in probed_keys]
    changed = [
        (old[key], new[key]) for key in old if key in new and old[key].service != new[key].service
    ]
    return Drift(
        new=tuple(sorted(appeared, key=sort_key)),
        closed=tuple(sorted(closed, key=sort_key)),
        changed=tuple(sorted(changed, key=lambda pair: sort_key(pair[0]))),
        not_scanned=tuple(sorted(skipped, key=sort_key)),
    )


def has_drift(drift: Drift) -> bool:
    """New, closed or changed entries count as drift; entries not scanned do not."""
    return bool(drift.new or drift.closed or drift.changed)
