"""The TLS prober: a handshake without verification, to read what the peer presents.

The connection comes from `AsyncioConnector` (so the scope policy is re-checked before any
socket exists), and is upgraded to TLS in place. Certificate verification is switched off on
purpose: the scanner wants to see whatever certificate a service presents, including expired,
self-signed and wrongly named ones, and it never sends application data after the handshake.
The peer's certificate is therefore read, not validated, and the report says so.

Every phase is bounded: connecting by `timeout`, the handshake by `timeout` (the inner
handshake timer is set one second longer, so the outer deadline is the one that decides), and
the close by `CLOSE_TIMEOUT_S`. A handshake that fails for any reason is a `ConnectError`
carrying a normalised code; the details of the failure, which come from the peer, are dropped.
The certificate is parsed by `describe_certificate`, which never raises for bad certificate
data. The TLS version offered is the library default (TLS 1.2 or newer): a server that only
speaks older versions shows up as a failed handshake, not a finding (PLAN.md risk R3).
"""

from __future__ import annotations

import asyncio
import ssl
from functools import cache

from network_scanner.core.errors import ConnectError, NetErrorCode
from network_scanner.core.interfaces import Clock
from network_scanner.core.model import TlsInfo
from network_scanner.net.certificate import describe_certificate
from network_scanner.net.connector import AsyncioConnector
from network_scanner.net.oserrors import normalise

HANDSHAKE_GRACE_S = 1.0  # the inner handshake timer outlasts the outer deadline by this much


@cache
def client_context() -> ssl.SSLContext:
    """A client context that accepts any certificate (see the module documentation)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # stated, not left to a build default
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class AsyncioTlsProber:
    def __init__(self, connector: AsyncioConnector, clock: Clock) -> None:
        self._connector = connector
        self._clock = clock

    async def handshake(
        self, address: str, port: int, *, server_name: str | None, timeout: float
    ) -> TlsInfo:
        connection = await self._connector.connect(address, port, timeout=timeout)
        try:
            try:
                async with asyncio.timeout(timeout):
                    await connection.start_tls(
                        client_context(),
                        server_name=server_name,
                        handshake_timeout=timeout + HANDSHAKE_GRACE_S,
                    )
            except TimeoutError:
                raise ConnectError(NetErrorCode.TIMEOUT) from None
            except OSError as exc:  # includes ssl.SSLError and resets
                raise ConnectError(normalise(exc)) from None
            version, cipher, der = connection.tls_session()
        except BaseException:
            await connection.abort()
            raise
        await connection.close()
        return describe_certificate(
            der,
            version=version,
            cipher=cipher,
            server_name=server_name,
            now=self._clock.utc_now(),
        )
