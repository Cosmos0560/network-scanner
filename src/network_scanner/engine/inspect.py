"""Probe an open port and describe what it said (passive banner, HTTP HEAD, TLS handshake).

The order and the limit on probes come from `probe_plan.next_probe`. Every probe is its own
connection, taken through the injected `Connector` (which re-checks the scope policy) after
the shared rate limiter, so the connection-rate cap covers probes as well as the scan itself,
and each probe has its own deadline. A probe that fails, resets or times out is simply not
answered; the inspector never raises for bad service data. A scope refusal from the
connector is a bug in the caller and propagates.
"""

from __future__ import annotations

import asyncio

from network_scanner.core.errors import ConnectError
from network_scanner.core.interfaces import Connection, Connector, RateLimiter, TlsProber
from network_scanner.core.limits import TLS_HANDSHAKE_TIMEOUT_S, Limits
from network_scanner.core.model import Observation, ResolvedTarget, TargetKind, TlsInfo
from network_scanner.engine.probe_plan import ProbeAttempt, ProbeKind, next_probe
from network_scanner.engine.probes import (
    BannerRead,
    HttpHead,
    build_head_request,
    host_header,
    http_head,
    read_banner,
)


class ServiceInspector:
    def __init__(
        self,
        *,
        limits: Limits,
        connector: Connector,
        tls_prober: TlsProber,
        limiter: RateLimiter,
        tool_version: str,
    ) -> None:
        self._limits = limits
        self._connector = connector
        self._tls_prober = tls_prober
        self._limiter = limiter
        self._tool_version = tool_version

    async def inspect(self, target: ResolvedTarget, port: int) -> Observation:
        hostname = target.display_name if target.origin_spec.kind is TargetKind.HOSTNAME else None
        banner = BannerRead(None, False)
        head: HttpHead | None = None
        tls: TlsInfo | None = None
        attempts: list[ProbeAttempt] = []
        while (
            kind := next_probe(port, attempts, max_probes=self._limits.probes_per_open_port)
        ) is not None:
            if kind is ProbeKind.BANNER:
                banner = await self._banner(target, port)
                answered = banner.text is not None
            elif kind is ProbeKind.HTTP_HEAD:
                head = await self._http_head(target, port, hostname)
                answered = head is not None
            else:
                tls = await self._tls(target, port, hostname)
                answered = tls is not None
            attempts.append(ProbeAttempt(kind, answered))
        answered_by = next((attempt.kind.value for attempt in attempts if attempt.answered), None)
        return Observation(
            banner=banner.text,
            banner_truncated=banner.truncated,
            probe=answered_by,
            http_status=None if head is None else head.status,
            http_server=None if head is None else head.server,
            tls=tls,
        )

    async def _open(self, target: ResolvedTarget, port: int) -> Connection | None:
        await self._limiter.acquire()
        timeout = self._limits.connect_timeout_s
        try:
            async with asyncio.timeout(timeout):
                return await self._connector.connect(target.address, port, timeout=timeout)
        except (ConnectError, TimeoutError, OSError):
            return None

    async def _banner(self, target: ResolvedTarget, port: int) -> BannerRead:
        connection = await self._open(target, port)
        if connection is None:
            return BannerRead(None, False)
        try:
            return await read_banner(
                connection,
                max_bytes=self._limits.banner_max_bytes,
                deadline_s=self._limits.banner_timeout_s,
            )
        finally:
            await connection.close()

    async def _http_head(
        self, target: ResolvedTarget, port: int, hostname: str | None
    ) -> HttpHead | None:
        connection = await self._open(target, port)
        if connection is None:
            return None
        request = build_head_request(
            host_header(target.address, port, hostname=hostname), self._tool_version
        )
        try:
            return await http_head(
                connection, request=request, deadline_s=self._limits.banner_timeout_s
            )
        finally:
            await connection.close()

    async def _tls(self, target: ResolvedTarget, port: int, hostname: str | None) -> TlsInfo | None:
        await self._limiter.acquire()
        try:
            # The prober connects and handshakes, each within TLS_HANDSHAKE_TIMEOUT_S.
            async with asyncio.timeout(2 * TLS_HANDSHAKE_TIMEOUT_S):
                return await self._tls_prober.handshake(
                    target.address, port, server_name=hostname, timeout=TLS_HANDSHAKE_TIMEOUT_S
                )
        except (ConnectError, TimeoutError, OSError):
            return None
