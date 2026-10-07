"""The TCP connector: the only place in the package that opens a connection to a target.

Every `connect` re-checks the scope policy before a socket exists. The address must be a
plain IP literal (never a name, so nothing is resolved here), it must be allowed by the same
`ScopeOptions` the plan was made with, and the port must be valid. A caller that bypasses
the planner and asks for a refused address gets `ScopeRefusal` and no socket.
`scripts/check_architecture.py` rejects any other module that calls an asyncio or socket
connect function.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket

from network_scanner.core.errors import ConnectError, NetErrorCode, ReasonCode, ScopeRefusal
from network_scanner.core.interfaces import Connection
from network_scanner.core.model import Family
from network_scanner.net.oserrors import normalise
from network_scanner.scope.parser import parse_ip
from network_scanner.scope.policy import ScopeOptions, decide_address

MAX_PORT = 65535


class AsyncioConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(self._reader.read(max_bytes), timeout)
        except TimeoutError:
            return b""
        except OSError as exc:
            raise ConnectError(normalise(exc)) from None

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        try:
            await self._writer.drain()
        except OSError as exc:
            raise ConnectError(normalise(exc)) from None

    async def close(self) -> None:
        self._writer.close()
        with contextlib.suppress(OSError):  # a reset peer: the connection is closed either way
            await self._writer.wait_closed()


class AsyncioConnector:
    def __init__(self, options: ScopeOptions) -> None:
        self._options = options

    def _approve(self, address: str, port: int) -> socket.AddressFamily:
        if not 1 <= port <= MAX_PORT:
            raise ValueError("port out of range")
        parsed = parse_ip(address)  # a name, CIDR or odd form is refused here
        decision = decide_address(parsed, self._options)
        if not decision.allowed:
            raise ScopeRefusal(
                decision.reason_code or ReasonCode.ALWAYS_REFUSED,
                address,
                f"the connector refused the address (class {decision.address_class.value})",
            )
        return socket.AF_INET if parsed.family is Family.IPV4 else socket.AF_INET6

    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        family = self._approve(address, port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port, family=family, flags=socket.AI_NUMERICHOST),
                timeout,
            )
        except TimeoutError:
            raise ConnectError(NetErrorCode.TIMEOUT) from None
        except OSError as exc:
            raise ConnectError(normalise(exc)) from None
        return AsyncioConnection(reader, writer)
