"""The mock lab's services: four loopback listeners with known fingerprints.

- an SSH-like service that sends an identification string and closes;
- a telnet-like service that sends option bytes and a login prompt and closes;
- an HTTP service that answers `HEAD` and `GET` with a fixed `Server` header, and answers
  anything else (such as a TLS ClientHello) with `400 Bad Request`;
- a TLS service with an ephemeral certificate. The certificate and key are generated at runtime
  (decision D2), written into a temporary directory only long enough for the TLS library to
  load them, and that directory is deleted straight away, so no key outlives the load.

They are only for tests and the demo: they bind loopback on OS-assigned ports, speak just
enough protocol to be recognised, and are not real SSH, telnet, HTTP or TLS servers. The lab
counts finished connections per service so a test can wait for the server side to settle
before it closes the lab (closing earlier abandons connections still being accepted).
Hostile servers live in `tests/`, not here.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import tempfile
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import TracebackType

from network_scanner.core.limits import CLOSE_TIMEOUT_S
from network_scanner.lab.certs import LabCertificate, default_lab_certificate
from network_scanner.lab.servers import LOOPBACK_HOSTS, LabError

SSH_BANNER = b"SSH-2.0-NetworkScannerLab_1.0\r\n"
TELNET_BANNER = b"\xff\xfd\x18\xff\xfd\x20\r\nNetwork Scanner Lab (telnet-like)\r\nlogin: "
HTTP_SERVER = "NetworkScannerLab/1.0"
MAX_REQUEST_BYTES = 8192
YIELDS_ON_EXIT = 5

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class ServiceLab:
    """Async context manager that runs the four services and stops them on exit."""

    def __init__(self, *, host: str = "127.0.0.1", tls_certificate: LabCertificate | None = None):
        if host not in LOOPBACK_HOSTS:
            raise LabError("the lab binds loopback addresses only")
        self.host = host
        self._certificate = tls_certificate
        self.ports: dict[str, int] = {}
        self.sni_names: list[str | None] = []  # the server name each TLS client asked for
        self._servers: list[asyncio.Server] = []
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._handled: Counter[str] = Counter()
        self._changed = asyncio.Condition()

    @property
    def ssh_port(self) -> int:
        return self.ports["ssh"]

    @property
    def telnet_port(self) -> int:
        return self.ports["telnet"]

    @property
    def http_port(self) -> int:
        return self.ports["http"]

    @property
    def tls_port(self) -> int:
        return self.ports["tls"]

    def handled(self, service: str) -> int:
        """How many connections to `service` have been fully handled so far."""
        return self._handled[service]

    async def wait_handled(self, service: str, count: int) -> None:
        """Wait until `count` connections to `service` ("ssh", "telnet", "http", "tls") are done."""
        async with self._changed:
            await self._changed.wait_for(lambda: self._handled[service] >= count)

    async def wait_open(self, count: int) -> None:
        """Wait until exactly `count` connections are being handled right now."""
        async with self._changed:
            await self._changed.wait_for(lambda: len(self._writers) == count)

    # -- start and stop --------------------------------------------------------------------
    def _tls_context(self) -> ssl.SSLContext:
        certificate = self._certificate or default_lab_certificate()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.TemporaryDirectory() as directory:
            certificate_path, key_path = certificate.write_pem_files(Path(directory))
            context.load_cert_chain(certificate_path, key_path)
        # Both files are gone here: the key now exists only in memory.

        def remember(_: ssl.SSLObject, name: str | None, __: ssl.SSLContext) -> None:
            self.sni_names.append(name)

        context.sni_callback = remember
        return context

    def _tracked(self, service: str, handler: Handler) -> Handler:
        async def run(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:  # pragma: no branch  (always inside a task)
                self._tasks.add(task)
            self._writers.add(writer)
            async with self._changed:
                self._changed.notify_all()
            try:
                with contextlib.suppress(OSError):  # a client that vanished is not an error here
                    await handler(reader, writer)
            finally:
                writer.close()
                self._writers.discard(writer)
                if task is not None:  # pragma: no branch
                    self._tasks.discard(task)
                async with self._changed:
                    self._handled[service] += 1
                    self._changed.notify_all()

        return run

    async def __aenter__(self) -> ServiceLab:
        services: list[tuple[str, Handler, ssl.SSLContext | None]] = [
            ("ssh", self._send_banner(SSH_BANNER), None),
            ("telnet", self._send_banner(TELNET_BANNER), None),
            ("http", self._http, None),
            ("tls", self._hold_open, self._tls_context()),
        ]
        try:
            for name, handler, context in services:
                server = await asyncio.start_server(
                    self._tracked(name, handler), self.host, 0, ssl=context
                )
                self._servers.append(server)
                self.ports[name] = int(server.sockets[0].getsockname()[1])
        except OSError:
            await self.__aexit__(None, None, None)
            raise LabError(f"cannot bind {self.host} on this machine") from None
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for server in self._servers:
            server.close()
        for _ in range(
            YIELDS_ON_EXIT
        ):  # let connections accepted a moment ago reach their handlers
            await asyncio.sleep(0)
        for writer in list(self._writers):
            writer.transport.abort()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for server in self._servers:
            # Newer Pythons wait here for every connection; a bounded wait cannot hang a test.
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(CLOSE_TIMEOUT_S):
                    await server.wait_closed()
        self._servers.clear()
        self.ports = {}

    # -- the services ----------------------------------------------------------------------
    @staticmethod
    def _send_banner(banner: bytes) -> Handler:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(banner)
            await writer.drain()

        return handler

    @staticmethod
    async def _hold_open(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """After the TLS handshake, wait for the client to go away; say nothing."""
        await reader.read(1)

    @staticmethod
    async def _http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = bytearray()
        while b"\n" not in head and len(head) < MAX_REQUEST_BYTES:
            chunk = await reader.read(MAX_REQUEST_BYTES - len(head))
            if not chunk:
                break
            head += chunk
            if bytes(head[:1]) not in (b"H", b"G"):  # not a request we know: no need to read on
                break
        request_line = bytes(head).split(b"\n", 1)[0].rstrip(b"\r")
        if request_line.startswith((b"HEAD ", b"GET ")):
            status, body = b"200 OK", b"" if request_line.startswith(b"HEAD ") else b"lab\n"
        else:
            status, body = b"400 Bad Request", b""
        writer.write(
            b"HTTP/1.1 "
            + status
            + b"\r\nServer: "
            + HTTP_SERVER.encode("ascii")
            + b"\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
