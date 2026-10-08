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


# -- servers that are hostile to a TLS client ---------------------------------------------------


async def garbage_reply(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Answers the ClientHello with bytes that are not TLS, then closes."""
    writer.write(b"\x00\x01\x02garbage that is not a TLS record\xff\xfe" * 4)
    with contextlib.suppress(OSError):
        await writer.drain()
    await _finish(writer)


async def tls_alert(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Answers with a fatal TLS alert (handshake_failure) record, then closes."""
    writer.write(b"\x15\x03\x03\x00\x02\x02\x28")
    with contextlib.suppress(OSError):
        await writer.drain()
    await _finish(writer)


async def endless_garbage(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Never stops sending non-TLS bytes; ends when the client drops the connection."""
    try:
        while True:
            writer.write(b"\xde\xad\xbe\xef" * 1024)
            await writer.drain()
    except OSError:
        pass
    finally:
        await _finish(writer)


async def partial_tls_record(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Sends the start of a TLS handshake record, then goes silent (a slow drip that stops)."""
    writer.write(b"\x16\x03\x03\x00\x50\x02")
    with contextlib.suppress(OSError):
        await writer.drain()
    try:
        await reader.read()  # holds the connection open until the peer goes away
    finally:
        await _finish(writer)


# -- servers that are hostile to a banner reader ------------------------------------------------


async def endless_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Sends one endless 'line' (no line break), as fast as the client reads."""
    try:
        while True:
            writer.write(b"A" * 1024)
            await writer.drain()
    except OSError:
        pass
    finally:
        await _finish(writer)


async def slow_drip(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Sends one byte every 50 ms and never a line break (the drip is the point of the test)."""
    try:
        while True:
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.05)
    except OSError:
        pass
    finally:
        await _finish(writer)


def fixed_banner(data: bytes) -> Handler:
    """A server that sends `data` once and closes."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(data)
        with contextlib.suppress(OSError):
            await writer.drain()
        await _finish(writer)

    return handler
