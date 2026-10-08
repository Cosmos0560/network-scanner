"""End to end: lab services, the real connector and TLS prober, the inspector, the matcher.

A scan of loopback with an inspector attached, then `identify` with the built-in rules, must
give exact answers for the four lab services (ssh-like, telnet-like, HTTP, TLS). Hostile
servers must not stop the run or get past the caps. Everything is loopback on OS-assigned
ports, created and closed by the test.

Timing. A service that speaks first answers at once, so those scans use the longest banner wait
the limits allow (the read ends as soon as the line arrives). Services that wait for the client
(HTTP, TLS) never speak first, so waiting for them is pointless and the banner wait is made
short; the answer is "silent" however slow the machine is. The HTTP and TLS deadlines are
shortened only in the hostile-server tests, where the server never answers.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import pytest

import hostile
from network_scanner.core.limits import Limits
from network_scanner.core.model import (
    Confidence,
    Family,
    Observation,
    ResolvedTarget,
    Service,
    TargetKind,
    TargetSpec,
    TlsInfo,
)
from network_scanner.engine import inspect as inspect_module
from network_scanner.engine.inspect import ServiceInspector
from network_scanner.engine.scan import ScanStatus, run_scan
from network_scanner.fingerprint.match import identify
from network_scanner.lab.certs import issue
from network_scanner.lab.services import ServiceLab
from network_scanner.net.connector import AsyncioConnector
from network_scanner.net.ratelimit import TokenBucket
from network_scanner.net.system import AsyncioSleeper
from network_scanner.net.tls import AsyncioTlsProber
from network_scanner.rules.loader import builtin_fingerprint_rules
from network_scanner.scope.policy import ScopeOptions

pytestmark = pytest.mark.leakcheck

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
TARGET = ResolvedTarget(
    "127.0.0.1", "127.0.0.1", Family.IPV4, TargetSpec("127.0.0.1", TargetKind.IP)
)
SPEAKS_FIRST = Limits(banner_timeout_s=10.0, connect_timeout_s=10.0)
WAITS_FOR_CLIENT = Limits(banner_timeout_s=0.1, connect_timeout_s=10.0)


class FixedClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utc_now(self) -> datetime:
        return NOW


async def inspect_ports(ports: list[int], limits: Limits) -> tuple[Observation, ...]:
    options = ScopeOptions(False, False, None)
    connector = AsyncioConnector(options)
    clock = FixedClock()
    limiter = TokenBucket(rate=limits.connections_per_second, clock=clock, sleeper=AsyncioSleeper())
    inspector = ServiceInspector(
        limits=limits,
        connector=connector,
        tls_prober=AsyncioTlsProber(connector, clock),
        limiter=limiter,
        tool_version="9.9.9",
    )
    outcome = await run_scan(
        [TARGET],
        ports,
        limits=limits,
        connector=connector,
        limiter=limiter,
        clock=clock,
        tool_version="9.9.9",
        inspector=inspector,
    )
    assert outcome.status is ScanStatus.COMPLETED
    return tuple(found.observation for found in outcome.observations)


# -- the four lab services, with exact expected fingerprints ---------------------------------


def test_the_ssh_like_service_is_identified_from_its_banner_alone() -> None:
    async def main() -> Observation:
        async with ServiceLab() as lab:
            (seen,) = await inspect_ports([lab.ssh_port], SPEAKS_FIRST)
            await lab.wait_handled("ssh", 1)
            return seen

    seen = asyncio.run(main())
    assert seen == Observation("SSH-2.0-NetworkScannerLab_1.0", False, "banner", None, None, None)
    assert identify(seen, builtin_fingerprint_rules()) == Service(
        "ssh", "ssh-identification", Confidence.HIGH
    )


def test_the_telnet_like_service_is_identified_with_low_confidence() -> None:
    async def main() -> Observation:
        async with ServiceLab() as lab:
            (seen,) = await inspect_ports([lab.telnet_port], SPEAKS_FIRST)
            await lab.wait_handled("telnet", 1)
            return seen

    seen = asyncio.run(main())
    # The option bytes are not valid UTF-8 and become U+FFFD; the control bytes are removed.
    assert seen.banner == "\ufffd\ufffd\ufffd\ufffd   Network Scanner Lab (telnet-like)  login:"
    assert (seen.probe, seen.banner_truncated, seen.http_status, seen.tls) == (
        "banner",
        False,
        None,
        None,
    )
    assert identify(seen, builtin_fingerprint_rules()) == Service(
        "telnet", "telnet-login-prompt", Confidence.LOW
    )


def test_the_http_service_is_identified_from_a_head_request() -> None:
    async def main() -> Observation:
        async with ServiceLab() as lab:
            (seen,) = await inspect_ports([lab.http_port], WAITS_FOR_CLIENT)
            await lab.wait_handled("http", 1)
            return seen

    seen = asyncio.run(main())
    assert seen == Observation(None, False, "http_head", 200, "NetworkScannerLab/1.0", None)
    assert identify(seen, builtin_fingerprint_rules()) == Service(
        "http", "http-status-line", Confidence.HIGH
    )


def test_the_tls_service_is_identified_from_its_handshake_and_certificate() -> None:
    given = issue(
        common_name="lab.test",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        dns_names=("lab.test",),
        ip_addresses=("127.0.0.1",),
    )

    async def main() -> Observation:
        async with ServiceLab(tls_certificate=given) as lab:
            (seen,) = await inspect_ports([lab.tls_port], WAITS_FOR_CLIENT)
            await lab.wait_handled("tls", 1)
            return seen

    seen = asyncio.run(main())
    assert (seen.banner, seen.probe, seen.http_status, seen.http_server) == (
        None,
        "tls",
        None,
        None,
    )
    tls = seen.tls
    assert isinstance(tls, TlsInfo)
    assert tls.version in ("TLSv1.2", "TLSv1.3")
    assert (tls.subject, tls.issuer, tls.san) == (
        "CN=lab.test",
        "CN=lab.test",
        ("DNS:lab.test", "IP:127.0.0.1"),
    )
    assert (tls.self_issued, tls.self_signature_valid, tls.expired) == (True, True, False)
    assert tls.hostname_match is None  # an IP target sends no name, so there is nothing to match
    assert identify(seen, builtin_fingerprint_rules()) == Service(
        "tls", "tls-handshake", Confidence.HIGH
    )


def test_each_open_port_gets_at_most_the_configured_number_of_connections() -> None:
    """The lab counts finished connections per service: the web server saw one HEAD, no more."""

    async def main() -> tuple[int, int]:
        async with ServiceLab() as lab:
            await inspect_ports([lab.http_port], WAITS_FOR_CLIENT)
            # The scan's own connect, the banner connection (which sent nothing) and one HEAD.
            await lab.wait_handled("http", 3)
            return lab.handled("http"), lab.handled("tls")

    assert asyncio.run(main()) == (3, 0)


# -- hostile servers through the whole pipeline ----------------------------------------------


@pytest.fixture
def short_deadlines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inspect_module, "HTTP_HEAD_TIMEOUT_S", 0.3)
    monkeypatch.setattr(inspect_module, "TLS_HANDSHAKE_TIMEOUT_S", 0.3)


async def inspect_hostile(handler: hostile.Handler, limits: Limits) -> tuple[Observation, int]:
    async with hostile.serve(handler) as served:
        (seen,) = await inspect_ports([served.port], limits)
        # The scan's connect, the banner probe and at most two more probes.
        await served.wait_handled(1)
        return seen, served.handled


def test_an_endless_banner_is_cut_at_the_byte_and_character_caps(short_deadlines: None) -> None:
    limits = Limits(banner_timeout_s=10.0, banner_max_bytes=512, connect_timeout_s=10.0)
    seen, _ = asyncio.run(inspect_hostile(hostile.endless_banner, limits))
    assert seen.probe == "banner"
    assert seen.banner_truncated is True
    assert seen.banner is not None
    assert len(seen.banner) == 256
    assert seen.banner.endswith("...")
    assert set(seen.banner[:-3]) == {"A"}


def test_a_slow_drip_banner_ends_at_the_deadline(short_deadlines: None) -> None:
    limits = Limits(banner_timeout_s=0.3, connect_timeout_s=10.0)
    seen, _ = asyncio.run(inspect_hostile(hostile.slow_drip, limits))
    assert seen.banner is None or set(seen.banner) == {"x"}
    assert seen.banner is None or len(seen.banner) < 100


@pytest.mark.parametrize(
    "handler",
    [hostile.accept_then_close, hostile.reset, hostile.silent],
    ids=lambda handler: handler.__name__,
)
def test_servers_that_say_nothing_give_an_empty_observation(
    handler: hostile.Handler, short_deadlines: None
) -> None:
    seen, _ = asyncio.run(inspect_hostile(handler, WAITS_FOR_CLIENT))
    assert seen == Observation(None, False, None, None, None, None)


def test_tls_garbage_is_taken_as_a_banner_and_sanitised(short_deadlines: None) -> None:
    seen, _ = asyncio.run(inspect_hostile(hostile.garbage_reply, SPEAKS_FIRST))
    assert seen.probe == "banner"
    assert seen.banner is not None
    assert "\x00" not in seen.banner
    assert "\x01" not in seen.banner
    assert seen.tls is None


@pytest.mark.parametrize(
    ("raw", "service"),
    [
        (b"\x1b[31mSSH-2.0-evil\x1b[0m\x00\r\n", "ssh"),
        (b"SSH-2.0-\xe2\x80\xaeevil\r\n", "ssh"),  # a bidi override inside the text
        (b"SSH-2.0-bad\xff\xfe-bytes\r\n", "ssh"),
        (b"\x1b]0;SSH-2.0-title-only\x07\r\n", None),  # an escape sequence is not a banner
    ],
)
def test_hostile_banner_text_is_sanitised_before_it_is_matched(
    raw: bytes, service: str | None, short_deadlines: None
) -> None:
    seen, _ = asyncio.run(inspect_hostile(hostile.fixed_banner(raw), SPEAKS_FIRST))
    assert seen.banner is not None
    for forbidden in ("\x1b", "\u202e", "\x00"):
        assert forbidden not in seen.banner
    found = identify(seen, builtin_fingerprint_rules())
    assert (found.name if found else None) == service
