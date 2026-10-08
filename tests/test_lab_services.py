"""The lab's four services, spoken to with plain asyncio clients on loopback.

Every server is started and closed by the test, on OS-assigned ports. The TLS service uses a
certificate generated at runtime (decision D2); one test checks that the temporary directory
it needs is gone as soon as the key has been loaded.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import tempfile
from pathlib import Path

import pytest

from network_scanner.lab.certs import LabCertificate
from network_scanner.lab.servers import LabError
from network_scanner.lab.services import (
    HTTP_SERVER,
    SSH_BANNER,
    TELNET_BANNER,
    ServiceLab,
)

pytestmark = pytest.mark.leakcheck


async def exchange(host: str, port: int, send: bytes = b"") -> bytes:
    """Connect, optionally send, read until the server closes (the lab's replies are short)."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        if send:
            writer.write(send)
            await writer.drain()
        return await asyncio.wait_for(reader.read(), 30)
    finally:
        writer.close()
        await writer.wait_closed()


def client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def test_each_service_says_what_its_fingerprint_expects() -> None:
    async def main() -> None:
        async with ServiceLab() as lab:
            assert await exchange(lab.host, lab.ssh_port) == SSH_BANNER
            assert await exchange(lab.host, lab.telnet_port) == TELNET_BANNER
            head = await exchange(lab.host, lab.http_port, b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert head == (
                b"HTTP/1.1 200 OK\r\nServer: "
                + HTTP_SERVER.encode()
                + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            get = await exchange(lab.host, lab.http_port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert get.endswith(b"Content-Length: 4\r\nConnection: close\r\n\r\nlab\n")
            for name in ("ssh", "telnet"):
                await lab.wait_handled(name, 1)
            await lab.wait_handled("http", 2)

    asyncio.run(main())


def test_the_http_service_answers_anything_else_with_400() -> None:
    async def main() -> None:
        async with ServiceLab() as lab:
            hello = bytes([0x16, 0x03, 0x01, 0x00, 0x20]) + b"\x01" * 32  # looks like a ClientHello
            reply = await exchange(lab.host, lab.http_port, hello)
            assert reply.startswith(b"HTTP/1.1 400 Bad Request\r\n")
            post = await exchange(lab.host, lab.http_port, b"POST / HTTP/1.1\r\n\r\n")
            assert post.startswith(b"HTTP/1.1 400 Bad Request\r\n")
            await lab.wait_handled("http", 2)

    asyncio.run(main())


def test_the_http_service_survives_a_client_that_closes_without_sending() -> None:
    async def main() -> None:
        async with ServiceLab() as lab:
            _, writer = await asyncio.open_connection(lab.host, lab.http_port)
            writer.close()
            await writer.wait_closed()
            await lab.wait_handled("http", 1)

    asyncio.run(main())


def test_the_tls_service_completes_a_handshake_and_records_the_server_name() -> None:
    async def main() -> None:
        async with ServiceLab() as lab:
            for name in ("lab.test", None):
                reader, writer = await asyncio.open_connection(
                    lab.host, lab.tls_port, ssl=client_context(), server_hostname=name
                )
                ssl_object = writer.get_extra_info("ssl_object")
                assert ssl_object.version() in ("TLSv1.2", "TLSv1.3")
                writer.close()
                await writer.wait_closed()
                del reader
            await lab.wait_handled("tls", 2)
            assert lab.sni_names == ["lab.test", None]

    asyncio.run(main())


def test_the_tls_service_presents_the_certificate_it_was_given(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from network_scanner.lab.certs import issue

    given = issue(
        common_name="given.test",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        dns_names=("given.test",),
    )

    async def main() -> bytes | None:
        async with ServiceLab(tls_certificate=given) as lab:
            reader, writer = await asyncio.open_connection(
                lab.host, lab.tls_port, ssl=client_context()
            )
            der: bytes | None = writer.get_extra_info("ssl_object").getpeercert(True)
            writer.close()
            await writer.wait_closed()
            del reader
            await lab.wait_handled("tls", 1)
            return der

    assert asyncio.run(main()) == given.der


def test_the_key_and_certificate_files_are_deleted_as_soon_as_they_are_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    seen: list[tuple[Path, Path]] = []
    original = LabCertificate.write_pem_files

    def recording(self: LabCertificate, directory: Path) -> tuple[Path, Path]:
        paths = original(self, directory)
        assert all(path.is_file() for path in paths)  # they exist while the lab loads them
        seen.append(paths)
        return paths

    monkeypatch.setattr(LabCertificate, "write_pem_files", recording)

    async def main() -> None:
        async with ServiceLab():
            assert len(seen) == 1
            assert not any(path.exists() for path in seen[0])  # deleted before the lab serves
            assert list(tmp_path.iterdir()) == []

    asyncio.run(main())
    assert list(tmp_path.iterdir()) == []


def test_the_ports_are_distinct_os_assigned_and_released_on_exit() -> None:
    async def main() -> list[int]:
        lab = ServiceLab()
        async with lab:
            ports = [lab.ssh_port, lab.telnet_port, lab.http_port, lab.tls_port]
            assert len(set(ports)) == 4
            assert all(1024 <= port <= 65535 for port in ports)
        assert lab.ports == {}
        return ports

    # A refused connection takes about two seconds on Windows (docs/performance.md), so the
    # release is checked by binding each port instead of connecting to it.
    for port in asyncio.run(main()):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "192.168.1.1", "8.8.8.8", "localhost", "", "127.0.0.2"]
)
def test_the_lab_binds_the_two_loopback_addresses_and_nothing_else(host: str) -> None:
    with pytest.raises(LabError, match="loopback"):
        ServiceLab(host=host)


def test_leaving_the_lab_aborts_connections_that_are_still_open() -> None:
    async def main() -> bytes:
        lab = ServiceLab()
        async with lab:
            reader, writer = await asyncio.open_connection(
                lab.host, lab.tls_port, ssl=client_context()
            )
            await lab.wait_open(1)  # the TLS handler is now waiting for this client
        # The lab is closed and returned; the client sees its connection end.
        try:
            return await asyncio.wait_for(reader.read(), 30)
        except OSError:
            return b""  # an abort may surface as a reset
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    assert asyncio.run(main()) == b""


def test_a_failed_bind_closes_what_was_opened(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    real = asyncio.start_server

    async def flaky(*args: object, **kwargs: object) -> asyncio.Server:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("synthetic bind failure")
        return await real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "start_server", flaky)

    async def main() -> None:
        with pytest.raises(LabError, match="cannot bind"):
            await ServiceLab().__aenter__()

    asyncio.run(main())
    assert calls == 3


def test_the_ipv6_lab_works_or_says_why_it_cannot() -> None:
    async def main() -> bytes:
        async with ServiceLab(host="::1") as lab:
            reply = await exchange("::1", lab.ssh_port)
            await lab.wait_handled("ssh", 1)
            return reply

    try:
        assert asyncio.run(main()) == SSH_BANNER
    except LabError as error:
        pytest.skip(f"no IPv6 loopback on this machine: {error}")
