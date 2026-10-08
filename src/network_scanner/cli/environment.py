"""Everything the CLI takes from the outside world, in one place so tests can replace it."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TextIO

from network_scanner.core.interfaces import Clock, Connector, Resolver, Sleeper, TlsProber
from network_scanner.net.connector import AsyncioConnector
from network_scanner.net.resolver import SystemResolver
from network_scanner.net.system import AsyncioSleeper, SystemClock
from network_scanner.net.tls import AsyncioTlsProber
from network_scanner.scope.policy import ScopeOptions


@dataclass(frozen=True)
class Environment:
    stdout: TextIO
    stderr: TextIO
    interactive: bool  # a person can answer a prompt
    ask: Callable[[str], str]
    resolver: Resolver
    clock: Clock
    sleeper: Sleeper
    connector_factory: Callable[[ScopeOptions], Connector]
    tls_prober_factory: Callable[[ScopeOptions, Clock], TlsProber]


def real_tls_prober(options: ScopeOptions, clock: Clock) -> TlsProber:
    """The real TLS prober; it connects through its own policy-checking connector."""
    return AsyncioTlsProber(AsyncioConnector(options), clock)


def default_environment() -> Environment:
    stdin = sys.stdin
    return Environment(
        stdout=sys.stdout,
        stderr=sys.stderr,
        interactive=stdin is not None and stdin.isatty(),
        ask=input,
        resolver=SystemResolver(),
        clock=SystemClock(),
        sleeper=AsyncioSleeper(),
        connector_factory=AsyncioConnector,
        tls_prober_factory=real_tls_prober,
    )
