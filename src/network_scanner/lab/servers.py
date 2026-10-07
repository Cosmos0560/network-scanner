"""The plain-TCP mock lab: loopback listeners with known states, for tests and the demo.

Only the two loopback addresses are accepted. Every port is assigned by the operating
system (bind to port 0), so there is no fixed port to collide with.

- An "open" port is a listening socket. The kernel completes the handshake without any
  Python code running, so a connect to it succeeds and the scanner closes it again.
- A "closed" port is a socket that is bound but never listens. Nothing else can take the
  port while the lab is open, so "closed" cannot turn into "open" by a race, which a port
  that was merely free once could. Connecting to it is refused.

Hostile servers (accept then close, reset, endless banner and so on) are test-only and live
in `tests/`, not in this package.
"""

from __future__ import annotations

import socket
import sys
from contextlib import ExitStack
from types import TracebackType

from network_scanner.core.errors import NetworkScannerError

LOOPBACK_HOSTS = ("127.0.0.1", "::1")
MAX_LAB_PORTS = 64


class LabError(NetworkScannerError):
    """The lab could not be set up (for example, no IPv6 loopback on this machine)."""


class PlainLab:
    """Context manager that owns the lab sockets and closes all of them on exit."""

    def __init__(self, *, host: str = "127.0.0.1", open_count: int = 3, closed_count: int = 3):
        if host not in LOOPBACK_HOSTS:
            raise LabError("the lab binds loopback addresses only")
        if not (0 <= open_count <= MAX_LAB_PORTS and 0 <= closed_count <= MAX_LAB_PORTS):
            raise LabError(f"at most {MAX_LAB_PORTS} ports of each kind")
        self.host = host
        self._open_count = open_count
        self._closed_count = closed_count
        self._stack = ExitStack()
        self.open_ports: tuple[int, ...] = ()
        self.closed_ports: tuple[int, ...] = ()

    def _bind(self, *, listen: bool) -> int:
        family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            raise LabError(f"cannot create a socket for {self.host}") from None
        self._stack.callback(sock.close)
        try:
            if sys.platform == "win32":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((self.host, 0))
            if listen:
                sock.listen(socket.SOMAXCONN)
        except OSError:
            raise LabError(f"cannot bind {self.host} on this machine") from None
        port = sock.getsockname()[1]
        return int(port)

    def __enter__(self) -> PlainLab:
        with ExitStack() as setup:
            setup.push(self._stack)  # on failure below, everything opened so far is closed
            self.open_ports = tuple(self._bind(listen=True) for _ in range(self._open_count))
            self.closed_ports = tuple(self._bind(listen=False) for _ in range(self._closed_count))
            setup.pop_all()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stack.close()
        self.open_ports = ()
        self.closed_ports = ()
