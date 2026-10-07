"""Hostile loopback servers for tests. Test-only: they are not part of the package.

Every server binds 127.0.0.1 on an OS-assigned port (port 0) and is closed when its
context exits. Nothing here uses a fixed port or any other address.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def _finish(writer: asyncio.StreamWriter) -> None:
    """Close and wait until the transport is really gone, so nothing outlives the test."""
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def accept_then_close(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await _finish(writer)


async def reset(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    # SO_LINGER with a zero timeout makes close() send a RST instead of a FIN.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    await _finish(writer)


async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.read()  # holds the connection open until the peer goes away
    finally:
        await _finish(writer)


class Served:
    """A running test server: its port, and how many connections its handler has finished."""

    def __init__(self) -> None:
        self.port = 0
        self.handled = 0
        self._changed = asyncio.Condition()

    async def wait_handled(self, count: int) -> None:
        """Wait until `count` connections were fully handled.

        A scan can finish as soon as the kernel completes each handshake, before asyncio has
        accepted the connection. Closing the server at that point abandons connections in the
        middle of being accepted, so a test waits here first.
        """
        async with self._changed:
            await self._changed.wait_for(lambda: self.handled >= count)


@asynccontextmanager
async def serve(handler: Handler) -> AsyncIterator[Served]:
    """Run a server with `handler` on loopback (OS-assigned port)."""
    served = Served()

    async def counting(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await handler(reader, writer)
        finally:
            async with served._changed:
                served.handled += 1
                served._changed.notify_all()

    server = await asyncio.start_server(counting, "127.0.0.1", 0)
    served.port = int(server.sockets[0].getsockname()[1])
    try:
        yield served
    finally:
        server.close()
        await server.wait_closed()
