"""The TLS prober against real loopback servers, with certificates generated at runtime.

Each test starts the servers it needs and closes them again; ports are OS-assigned, nothing
leaves loopback, and no key or certificate is read from a file in the repository (D2). The
"now" the prober uses is injected, so a certificate's expiry never depends on the date.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from datetime import UTC, datetime
from typing import Any, cast

import pytest

import hostile
from network_scanner.core.errors import ConnectError, NetErrorCode, ReasonCode, ScopeRefusal
from network_scanner.core.limits import ABORT_GRACE_S, CLOSE_TIMEOUT_S, MAX_CERT_DER_BYTES
from network_scanner.core.model import TlsInfo
from network_scanner.lab.certs import KeyType, LabCertificate, issue, new_key
from network_scanner.lab.servers import PlainLab
from network_scanner.lab.services import ServiceLab
from network_scanner.net.certificate import CERTIFICATE_TOO_LARGE
from network_scanner.net.connector import AsyncioConnection, AsyncioConnector
from network_scanner.net.tls import AsyncioTlsProber, client_context
from network_scanner.scope.policy import ScopeOptions
from virtual_loop import run_virtual

pytestmark = pytest.mark.leakcheck

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 1, 1, tzinfo=UTC)
UNTIL = datetime(2027, 1, 1, tzinfo=UTC)
LOOPBACK_ONLY = ScopeOptions(False, False, None)
GENEROUS = 30.0  # seconds; a loopback handshake takes milliseconds, this only guards a hang


class FixedClock:
    def monotonic(self) -> float:
        return 0.0

    def utc_now(self) -> datetime:
        return NOW


def prober() -> AsyncioTlsProber:
    return AsyncioTlsProber(AsyncioConnector(LOOPBACK_ONLY), FixedClock())


def certificate(**overrides: Any) -> LabCertificate:
    settings: dict[str, Any] = {
        "common_name": "lab.test",
        "not_before": FROM,
        "not_after": UNTIL,
        "dns_names": ("lab.test",),
        "ip_addresses": ("127.0.0.1",),
    }
    settings.update(overrides)
    return issue(**settings)


async def probe_lab(
    given: LabCertificate, *, server_name: str | None = None, port_of: str = "tls"
) -> TlsInfo:
    async with ServiceLab(tls_certificate=given) as lab:
        info = await prober().handshake(
            "127.0.0.1", lab.ports[port_of], server_name=server_name, timeout=GENEROUS
        )
        await lab.wait_handled("tls", 1)
        return info


def handshake_facts(info: TlsInfo) -> TlsInfo:
    """The certificate facts, without the negotiated version and cipher (they depend on OpenSSL)."""
    assert info.version in ("TLSv1.2", "TLSv1.3")
    assert info.cipher
    return dataclasses.replace(info, version=None, cipher=None)


def expected(given: LabCertificate, **fields: Any) -> TlsInfo:
    base: dict[str, Any] = {
        "version": None,
        "cipher": None,
        "subject": "CN=lab.test",
        "issuer": "CN=lab.test",
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "san": ("DNS:lab.test", "IP:127.0.0.1"),
        "san_truncated": False,
        "sha256": hashlib.sha256(given.der).hexdigest(),
        "self_issued": True,
        "self_signature_valid": True,
        "expired": False,
        "hostname_match": True,
        "parse_error": None,
    }
    base.update(fields)
    return TlsInfo(**base)


# -- certificate fields, exactly, over a real handshake --------------------------------------


@pytest.mark.parametrize("key_type", list(KeyType))
def test_a_valid_self_signed_certificate_is_reported_exactly(key_type: KeyType) -> None:
    given = certificate(key_type=key_type)
    info = asyncio.run(probe_lab(given, server_name="lab.test"))
    assert handshake_facts(info) == expected(given)


def test_an_expired_certificate_is_reported_as_expired() -> None:
    given = certificate(not_before=datetime(2020, 1, 1, tzinfo=UTC), not_after=FROM)
    info = asyncio.run(probe_lab(given, server_name="lab.test"))
    assert handshake_facts(info) == expected(
        given,
        not_before="2020-01-01T00:00:00+00:00",
        not_after="2026-01-01T00:00:00+00:00",
        expired=True,
    )


def test_a_certificate_for_another_name_does_not_match_the_requested_name() -> None:
    given = certificate(common_name="other.test", dns_names=("other.test",), ip_addresses=())
    info = asyncio.run(probe_lab(given, server_name="lab.test"))
    assert handshake_facts(info) == expected(
        given,
        subject="CN=other.test",
        issuer="CN=other.test",
        san=("DNS:other.test",),
        hostname_match=False,
    )


def test_without_a_requested_name_the_match_is_unknown_not_false() -> None:
    info = asyncio.run(probe_lab(certificate(), server_name=None))
    assert info.hostname_match is None


def test_a_ca_issued_leaf_is_not_self_issued_and_does_not_verify_under_its_own_key() -> None:
    ca = certificate(common_name="Lab CA", is_ca=True, dns_names=(), ip_addresses=())
    leaf = certificate(issuer=ca)
    info = asyncio.run(probe_lab(leaf, server_name="lab.test"))
    assert handshake_facts(info) == expected(
        leaf, issuer="CN=Lab CA", self_issued=False, self_signature_valid=False
    )


def test_self_issued_and_self_signature_are_separate_facts_over_the_wire() -> None:
    forged = certificate(issuer_common_name="lab.test", signing_key=new_key())
    info = asyncio.run(probe_lab(forged, server_name="lab.test"))
    assert (info.self_issued, info.self_signature_valid) == (True, False)
    odd = certificate(issuer_common_name="Someone Else")
    info = asyncio.run(probe_lab(odd, server_name="lab.test"))
    assert (info.self_issued, info.self_signature_valid) == (False, True)


def test_the_server_name_is_sent_only_when_one_is_given() -> None:
    async def main() -> list[str | None]:
        async with ServiceLab() as lab:
            for name in ("lab.test", None):
                await prober().handshake(
                    "127.0.0.1", lab.tls_port, server_name=name, timeout=GENEROUS
                )
            await lab.wait_handled("tls", 2)
            return lab.sni_names

    assert asyncio.run(main()) == ["lab.test", None]


def test_an_oversized_certificate_is_not_parsed_but_the_handshake_still_counts() -> None:
    names = tuple(f"host-{n:05d}.example-lab-name.test" for n in range(2500))
    huge = certificate(dns_names=names, ip_addresses=())
    assert len(huge.der) > MAX_CERT_DER_BYTES
    info = asyncio.run(probe_lab(huge, server_name="lab.test"))
    assert info.version in ("TLSv1.2", "TLSv1.3")
    assert info.parse_error == CERTIFICATE_TOO_LARGE
    assert info.sha256 == hashlib.sha256(huge.der).hexdigest()
    assert (info.subject, info.san, info.expired) == (None, (), None)


# -- hostile servers -------------------------------------------------------------------------

REFUSAL_CODES = {NetErrorCode.OTHER, NetErrorCode.RESET}


async def probe_hostile(handler: hostile.Handler, *, timeout: float = GENEROUS) -> ConnectError:
    async with hostile.serve(handler) as served:
        with pytest.raises(ConnectError) as caught:
            await prober().handshake("127.0.0.1", served.port, server_name=None, timeout=timeout)
        await served.wait_handled(1)
    return caught.value


@pytest.mark.parametrize(
    "handler",
    [
        hostile.accept_then_close,
        hostile.reset,
        hostile.garbage_reply,
        hostile.tls_alert,
        hostile.endless_garbage,
    ],
    ids=lambda handler: handler.__name__,
)
def test_a_server_that_does_not_speak_tls_is_a_failed_handshake(handler: hostile.Handler) -> None:
    error = asyncio.run(probe_hostile(handler))
    assert error.code in REFUSAL_CODES


@pytest.mark.parametrize(
    "handler", [hostile.silent, hostile.partial_tls_record], ids=lambda h: h.__name__
)
def test_a_server_that_never_finishes_the_handshake_times_out(handler: hostile.Handler) -> None:
    error = asyncio.run(probe_hostile(handler, timeout=0.5))
    assert error.code is NetErrorCode.TIMEOUT


def test_a_plain_http_service_is_a_failed_handshake() -> None:
    async def main() -> NetErrorCode:
        async with ServiceLab() as lab:
            with pytest.raises(ConnectError) as caught:
                await prober().handshake(
                    "127.0.0.1", lab.http_port, server_name=None, timeout=GENEROUS
                )
            await lab.wait_handled("http", 1)
            return caught.value.code

    assert asyncio.run(main()) in REFUSAL_CODES


def test_a_closed_port_is_refused() -> None:
    with PlainLab(open_count=0, closed_count=1) as lab, pytest.raises(ConnectError) as caught:
        asyncio.run(
            prober().handshake("127.0.0.1", lab.closed_ports[0], server_name=None, timeout=GENEROUS)
        )
    assert caught.value.code is NetErrorCode.REFUSED


# -- the scope policy still applies ----------------------------------------------------------


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "169.254.169.254", "224.0.0.1", "example.test", "::ffff:10.0.0.1"]
)
def test_the_prober_cannot_be_pointed_at_an_address_the_policy_refuses(address: str) -> None:
    with pytest.raises(ScopeRefusal) as caught:
        asyncio.run(prober().handshake(address, 443, server_name=None, timeout=GENEROUS))
    assert caught.value.reason_code in set(ReasonCode)


def test_the_client_context_accepts_any_certificate_by_design() -> None:
    import ssl

    context = client_context()
    assert context.verify_mode is ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert client_context() is context  # built once


# -- closing --------------------------------------------------------------------------------


class StubTransport:
    def __init__(self) -> None:
        self.aborted = 0

    def abort(self) -> None:
        self.aborted += 1


class StuckWriter:
    """A writer whose close never completes, like a peer that ignores a TLS close_notify."""

    def __init__(self) -> None:
        self.transport = StubTransport()
        self.closing = 0
        self._release = asyncio.Event()

    def close(self) -> None:
        self.closing += 1

    async def wait_closed(self) -> None:
        if self.transport.aborted:
            return
        await self._release.wait()


def test_a_peer_that_never_finishes_closing_is_aborted_after_the_close_timeout() -> None:
    async def main() -> tuple[float, int, int]:
        loop = asyncio.get_running_loop()
        writer = StuckWriter()
        connection = AsyncioConnection(cast(Any, None), cast(Any, writer))
        started = loop.time()
        await connection.close()
        return loop.time() - started, writer.closing, writer.transport.aborted

    elapsed, closes, aborts = run_virtual(main)
    assert (elapsed, closes, aborts) == (CLOSE_TIMEOUT_S, 1, 1)


def test_abort_returns_even_when_the_connection_never_reports_closed() -> None:
    async def main() -> tuple[float, int]:
        loop = asyncio.get_running_loop()
        writer = StuckWriter()
        writer.transport.aborted = 0
        connection = AsyncioConnection(cast(Any, None), cast(Any, writer))

        async def never() -> None:
            await asyncio.sleep(10**9)

        writer.wait_closed = never  # type: ignore[method-assign]
        started = loop.time()
        await connection.abort()
        return loop.time() - started, writer.transport.aborted

    elapsed, aborts = run_virtual(main)
    assert (elapsed, aborts) == (ABORT_GRACE_S, 1)


def test_a_connection_that_is_not_tls_has_no_session_details() -> None:
    class PlainWriter:
        def get_extra_info(self, name: str) -> None:
            return None

    connection = AsyncioConnection(cast(Any, None), cast(Any, PlainWriter()))
    assert connection.tls_session() == (None, None, None)
