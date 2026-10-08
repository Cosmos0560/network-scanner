"""Which probe to try next on an open port. Pure: no I/O, no clock.

Probing is passive and minimal (PLAN.md section 4.6): at most `probes_per_open_port`
connections, each doing one thing.

1. `banner`: connect and read what the service says unprompted. Protocols such as SSH, FTP,
   SMTP, POP3, IMAP and VNC speak first, so most are identified here, having been sent nothing.
2. If nothing was said, the service is waiting for the client. Two more probes are tried, in an
   order that depends only on the port number, until one gets an answer:
   - `http_head`: one `HEAD /` request, no body, no credentials;
   - `tls`: a TLS handshake, then the connection is closed; nothing is sent after it.

The port number only chooses the order (a port that is normally TLS-wrapped tries TLS first);
both are tried whatever the port, because a service can run on any port. As soon as one probe
is answered the plan ends, and a service that spoke first is never sent anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum


class ProbeKind(StrEnum):
    BANNER = "banner"
    HTTP_HEAD = "http_head"
    TLS = "tls"


# Ports that are normally TLS-wrapped from the first byte: https (443), smtps (465), nntps
# (563), ldaps (636), DNS over TLS (853), ftps (989, 990), telnets (992), imaps (993), pop3s
# (995), sips (5061), and the common alternative https ports 8443 and 9443.
TLS_FIRST_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 5061, 8443, 9443})


@dataclass(frozen=True, slots=True)
class ProbeAttempt:
    kind: ProbeKind
    answered: bool  # the probe got a usable answer (a banner, an HTTP status line, a handshake)


def next_probe(port: int, attempts: Sequence[ProbeAttempt], *, max_probes: int) -> ProbeKind | None:
    """The next probe to run after `attempts`, or None when the plan is finished."""
    if len(attempts) >= max_probes or any(attempt.answered for attempt in attempts):
        return None
    if not attempts:
        return ProbeKind.BANNER
    order = (
        (ProbeKind.TLS, ProbeKind.HTTP_HEAD)
        if port in TLS_FIRST_PORTS
        else (ProbeKind.HTTP_HEAD, ProbeKind.TLS)
    )
    tried = {attempt.kind for attempt in attempts}
    return next((kind for kind in order if kind not in tried), None)
