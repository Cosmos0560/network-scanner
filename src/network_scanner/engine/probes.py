"""Reading what a service sends: the banner and the head of an HTTP response.

Whatever a service sends is hostile input, so every read here is bounded three ways: by bytes
(`banner_max_bytes`, `MAX_HTTP_HEAD_BYTES`), by lines (`MAX_HTTP_HEADER_LINES`) and by one
deadline for the whole read, not per chunk, so a service that drips one byte at a time runs
out of time instead of keeping the scan waiting. Nothing is read until end of stream. All
text is passed through the sanitiser before it is returned. These functions work on the
`Connection` interface and never open anything themselves.

The only thing ever sent is one `HEAD / HTTP/1.1` request, built from a fixed template and
two validated values (the host and the tool version). No credentials, no body, no other
method, no payload that depends on what the service said.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from network_scanner.core.errors import ConnectError
from network_scanner.core.interfaces import Connection
from network_scanner.core.limits import (
    MAX_BANNER_CHARS,
    MAX_HTTP_HEAD_BYTES,
    MAX_HTTP_HEADER_LINES,
    MAX_HTTP_SERVER_CHARS,
)
from network_scanner.core.sanitize import sanitize_bytes

_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?")
_HOST = re.compile(r"[A-Za-z0-9.:-]{1,253}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_SERVER_HEADER_BYTES = 1024


@dataclass(frozen=True, slots=True)
class BannerRead:
    text: str | None  # None: the service said nothing; "" means only non-printable bytes
    truncated: bool


@dataclass(frozen=True, slots=True)
class HttpHead:
    status: int
    server: str | None


async def read_banner(connection: Connection, *, max_bytes: int, deadline_s: float) -> BannerRead:
    """Read what the service says unprompted: up to `max_bytes`, ending at the first line
    break, at end of stream, or when `deadline_s` runs out, whichever comes first."""
    data = bytearray()
    try:
        async with asyncio.timeout(deadline_s):
            while len(data) < max_bytes:
                chunk = await connection.read(max_bytes - len(data), timeout=deadline_s)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk or b"\r" in chunk:
                    break
    except (TimeoutError, ConnectError):
        pass  # what arrived before the deadline or the reset is still the banner
    if not data:
        return BannerRead(None, False)
    cleaned = sanitize_bytes(bytes(data), max_bytes=max_bytes, max_chars=MAX_BANNER_CHARS)
    return BannerRead(cleaned.text.strip(), cleaned.truncated or len(data) >= max_bytes)


def host_header(address: str, port: int, *, hostname: str | None) -> str:
    """The Host header value: the requested hostname, or the address literal (a zone id is
    dropped, an IPv6 literal gets brackets). Raises ValueError for anything unexpected, since
    both inputs come from the validated plan and a bad one is a bug, not hostile input."""
    name = hostname if hostname is not None else address.partition("%")[0]
    if _HOST.fullmatch(name) is None:
        raise ValueError("the host name or address is not in a form that can be sent")
    shown = f"[{name}]" if ":" in name else name
    return f"{shown}:{port}"


def build_head_request(host: str, tool_version: str) -> bytes:
    version = tool_version if _VERSION.fullmatch(tool_version) else "unknown"
    return (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: network-scanner/{version}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def parse_http_head(data: bytes) -> HttpHead | None:
    """The status code and Server header of an HTTP/1.x response head, or None if `data`
    does not start with a complete, valid status line. Only the first
    `MAX_HTTP_HEADER_LINES` header lines are looked at."""
    lines = data[:MAX_HTTP_HEAD_BYTES].split(b"\n", MAX_HTTP_HEADER_LINES + 1)
    if len(lines) < 2:  # the status line is not complete
        return None
    status = _STATUS_LINE.fullmatch(lines[0].rstrip(b"\r"))
    if status is None:
        return None
    server: str | None = None
    for raw in lines[1 : MAX_HTTP_HEADER_LINES + 1]:
        line = raw.rstrip(b"\r")
        if not line:
            break  # the blank line that ends the head
        name, colon, value = line.partition(b":")
        if colon and name.lower() == b"server" and server is None:
            cleaned = sanitize_bytes(
                value.strip(b" \t"), max_bytes=_SERVER_HEADER_BYTES, max_chars=MAX_HTTP_SERVER_CHARS
            )
            server = cleaned.text.strip() or None
    return HttpHead(int(status.group(1)), server)


async def http_head(
    connection: Connection, *, request: bytes, deadline_s: float
) -> HttpHead | None:
    """Send `request` and read the response head, within `deadline_s` and `MAX_HTTP_HEAD_BYTES`."""
    buffer = bytearray()
    try:
        async with asyncio.timeout(deadline_s):
            await connection.write(request)
            while len(buffer) < MAX_HTTP_HEAD_BYTES:
                chunk = await connection.read(MAX_HTTP_HEAD_BYTES - len(buffer), timeout=deadline_s)
                if not chunk:
                    break
                buffer += chunk
                if b"\r\n\r\n" in buffer or b"\n\n" in buffer:
                    break
    except (TimeoutError, ConnectError):
        pass  # a status line that arrived before the deadline or the reset still counts
    return parse_http_head(bytes(buffer))
