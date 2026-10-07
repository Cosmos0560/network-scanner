"""The system resolver adapter. Used only for hostname targets, once per name per run.

The lookup function is injectable so that no test needs real DNS. Whatever it returns is
untrusted: the scope policy parses and classifies every answer itself.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from typing import Any

from network_scanner.core.errors import ResolutionError

Lookup = Callable[[str], Awaitable[list[tuple[Any, ...]]]]
"""Takes a name and returns `getaddrinfo`-style tuples; raises OSError on failure."""


async def _system_lookup(name: str) -> list[tuple[Any, ...]]:  # pragma: no cover (real DNS)
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM)


class SystemResolver:
    def __init__(self, lookup: Lookup = _system_lookup) -> None:
        self._lookup = lookup

    async def resolve(self, name: str, *, timeout: float) -> tuple[str, ...]:
        try:
            infos = await asyncio.wait_for(self._lookup(name), timeout)
        except TimeoutError:
            raise ResolutionError("the lookup timed out") from None
        except OSError:
            raise ResolutionError("the lookup failed") from None
        addresses: dict[str, None] = {}
        for info in infos:
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and sockaddr and isinstance(sockaddr[0], str):
                addresses[sockaddr[0]] = None
        return tuple(addresses)
