"""Banner and HTTP HEAD reads: bounded in bytes, lines and time, and sanitised.

These run on virtual time against scripted streams, so a service that drips one byte per
half second costs no real time and the elapsed time can be asserted exactly.
"""

from __future__ import annotations

import asyncio

import pytest

from network_scanner.core.errors import NetErrorCode
from network_scanner.core.limits import (
    MAX_BANNER_CHARS,
    MAX_HTTP_HEAD_BYTES,
    MAX_HTTP_HEADER_LINES,
    MAX_HTTP_SERVER_CHARS,
)
from network_scanner.engine.probes import (
    BannerRead,
    HttpHead,
    build_head_request,
    host_header,
    http_head,
    parse_http_head,
    read_banner,
)
from probe_fakes import OverfullStream, ScriptedStream
from virtual_loop import run_virtual

pytestmark = pytest.mark.leakcheck

CAP = 1024
DEADLINE = 2.0


def banner_of(stream: ScriptedStream, *, deadline: float = DEADLINE) -> tuple[BannerRead, float]:
    async def main() -> tuple[BannerRead, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await read_banner(stream, max_bytes=CAP, deadline_s=deadline)
        return result, loop.time() - started

    return run_virtual(main)


# -- the passive banner read -----------------------------------------------------------------


def test_a_banner_is_read_up_to_the_end_of_its_line() -> None:
    stream = ScriptedStream([(0.0, b"SSH-2.0-Lab_1.0\r\n"), (0.0, b"never read\r\n")])
    result, elapsed = banner_of(stream)
    assert result == BannerRead("SSH-2.0-Lab_1.0", False)
    assert stream.delivered == len(b"SSH-2.0-Lab_1.0\r\n")
    assert elapsed == 0.0
    assert stream.written == []  # a service that speaks first is sent nothing


def test_a_banner_without_a_line_break_ends_with_the_stream() -> None:
    result, _ = banner_of(ScriptedStream([(0.0, b"login: ")]))
    assert result == BannerRead("login:", False)


def test_a_banner_in_several_chunks_is_joined_until_the_line_break() -> None:
    result, _ = banner_of(ScriptedStream([(0.1, b"SSH-2."), (0.1, b"0-Lab"), (0.1, b"\n")]))
    assert result.text == "SSH-2.0-Lab"


def test_a_silent_service_gives_no_banner_after_exactly_the_deadline() -> None:
    result, elapsed = banner_of(ScriptedStream(hang=True))
    assert result == BannerRead(None, False)
    assert elapsed == DEADLINE


def test_a_service_that_closes_at_once_gives_no_banner_and_takes_no_time() -> None:
    result, elapsed = banner_of(ScriptedStream())
    assert result == BannerRead(None, False)
    assert elapsed == 0.0


def test_an_endless_banner_stops_at_the_byte_cap() -> None:
    stream = ScriptedStream(endless=b"A")
    result, elapsed = banner_of(stream)
    assert stream.delivered == CAP
    assert sum(stream.requested) <= CAP * 2  # asked for the remainder each time, never more
    assert max(stream.requested) <= CAP
    assert result.truncated is True
    assert result.text is not None
    assert len(result.text) == MAX_BANNER_CHARS
    assert result.text.endswith("...")
    assert elapsed == 0.0


def test_a_banner_of_exactly_the_cap_is_marked_truncated() -> None:
    result, _ = banner_of(ScriptedStream([(0.0, b"B" * CAP)]))
    assert result.truncated is True


def test_a_long_first_line_is_cut_to_the_character_cap() -> None:
    result, _ = banner_of(ScriptedStream([(0.0, b"C" * 500 + b"\n")]))
    assert result.text is not None
    assert (len(result.text), result.truncated) == (MAX_BANNER_CHARS, True)


def test_a_slow_drip_runs_out_of_time_instead_of_waiting_for_the_cap() -> None:
    stream = ScriptedStream([(0.5, b"x")] * 100)
    result, elapsed = banner_of(stream)
    assert elapsed == DEADLINE  # not 100 x 0.5 s
    assert result.text == "xxx"  # the bytes at 0.5, 1.0 and 1.5 s; the one at 2.0 s is too late
    assert stream.delivered == 3


def test_a_drip_that_never_ends_a_line_is_still_bounded_by_the_deadline() -> None:
    stream = ScriptedStream([(0.1, b"y")] * 10_000)
    result, elapsed = banner_of(stream, deadline=1.0)
    assert elapsed == pytest.approx(1.0)  # ten steps of 0.1 s add up with rounding
    assert result.text is not None
    assert len(result.text) < 20


def test_a_reset_keeps_what_arrived_before_it() -> None:
    class ResetAfterData(ScriptedStream):
        async def read(self, max_bytes: int, *, timeout: float) -> bytes:
            if self.requested:
                self._read_error = NetErrorCode.RESET
            return await super().read(max_bytes, timeout=timeout)

    result, _ = banner_of(ResetAfterData([(0.0, b"partial")]))
    assert result.text == "partial"


def test_a_reset_before_any_data_gives_no_banner() -> None:
    result, _ = banner_of(ScriptedStream(read_error=NetErrorCode.RESET))
    assert result == BannerRead(None, False)


def test_a_connection_that_returns_too_much_is_cut_at_the_cap() -> None:
    result, _ = banner_of(OverfullStream(b"Z" * (CAP * 3)))
    assert result.truncated is True
    assert result.text is not None
    assert len(result.text) == MAX_BANNER_CHARS


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"\x1b[31mred\x1b[0m\r\n", "red"),
        (b"a\x00b\x07c\x7fd", "abcd"),
        (b"safe\x1b]0;title\x07 tail", "safe tail"),
        ("before\u202eafter".encode(), "beforeafter"),
        (b"bad \xff\xfe bytes", "bad \ufffd\ufffd bytes"),
        (b"\xff\xfd\x18\xff\xfd\x20 ready", "\ufffd\ufffd\ufffd\ufffd  ready"),  # telnet options
        (b"tab\there", "tab here"),
        (b"\x00\x00\x00", ""),  # bytes arrived, none printable
        (b"  spaced  \r\n", "spaced"),
    ],
)
def test_banner_text_is_sanitised(raw: bytes, expected: str) -> None:
    result, _ = banner_of(ScriptedStream([(0.0, raw)]))
    assert result.text is not None
    assert result.text == expected


# -- HTTP response heads ---------------------------------------------------------------------

OK = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Length: 0\r\n\r\n"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (OK, HttpHead(200, "nginx/1.25")),
        (b"HTTP/1.0 404 Not Found\r\n\r\n", HttpHead(404, None)),
        (b"HTTP/1.1 204\r\nserver: x\r\n\r\n", HttpHead(204, "x")),
        (b"HTTP/1.1 301 Moved\nServer: bare-lf\n\n", HttpHead(301, "bare-lf")),
        (b"HTTP/1.1 100 Continue\r\n", HttpHead(100, None)),
        (b"HTTP/1.1 599 Odd\r\nSERVER:   padded value  \r\n\r\n", HttpHead(599, "padded value")),
        (b"HTTP/1.1 200 OK\r\nServer: first\r\nServer: second\r\n\r\n", HttpHead(200, "first")),
        (b"HTTP/1.1 200 OK\r\nServer:\r\n\r\n", HttpHead(200, None)),
        (b"HTTP/1.1 200 OK\r\nServer: \x1b[31mred\x00\r\n\r\n", HttpHead(200, "red")),
        (
            b"HTTP/1.1 200 OK\r\n continued: x\r\nServer: after-fold\r\n\r\n",
            HttpHead(200, "after-fold"),
        ),
        (b"HTTP/1.1 200 OK\r\n\r\nServer: in-the-body\r\n", HttpHead(200, None)),
        (b"HTTP/1.1 200 OK\r\nno colon here\r\nServer: ok\r\n\r\n", HttpHead(200, "ok")),
        (b"HTTP/1.1 200 \xff\xfe binary reason\r\nServer: ok\r\n\r\n", HttpHead(200, "ok")),
        (b"HTTP/1.1 200 OK\r\nServer: caf\xc3\xa9\r\n\r\n", HttpHead(200, "caf\u00e9")),
    ],
)
def test_valid_http_heads_are_parsed(data: bytes, expected: HttpHead) -> None:
    assert parse_http_head(data) == expected


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"HTTP/1.1 200 OK",  # the status line is not finished
        b"HTTP/2 200\r\n",
        b"HTTP/1.2 200 OK\r\n",
        b"http/1.1 200 OK\r\n",
        b"HTTP/1.1 99 Low\r\n",
        b"HTTP/1.1 600 High\r\n",
        b"HTTP/1.1 2000 Long\r\n",
        b"HTTP/1.1 abc OK\r\n",
        b"HTTP/1.1200 OK\r\n",
        b" HTTP/1.1 200 OK\r\n",
        b"SSH-2.0-OpenSSH_9.6\r\n",
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc",  # the start of a TLS record
        b"\x15\x03\x03\x00\x02\x02\x46",  # a TLS alert
        b"\x00\x01\x02\x03",
        b"<html>not http</html>\r\n",
    ],
    ids=range(16),
)
def test_other_data_is_not_an_http_head(data: bytes) -> None:
    assert parse_http_head(data) is None


def test_only_the_first_header_lines_are_looked_at() -> None:
    filler = b"X-Pad: 1\r\n" * (MAX_HTTP_HEADER_LINES - 1)
    inside = b"HTTP/1.1 200 OK\r\n" + filler + b"Server: last-line\r\n\r\n"
    outside = b"HTTP/1.1 200 OK\r\n" + filler + b"X-Pad: 2\r\nServer: too-late\r\n\r\n"
    assert parse_http_head(inside) == HttpHead(200, "last-line")
    assert parse_http_head(outside) == HttpHead(200, None)


def test_only_the_first_bytes_of_the_head_are_looked_at() -> None:
    padding = b"X-Pad: " + b"p" * 100 + b"\r\n"
    count = MAX_HTTP_HEAD_BYTES // len(padding)
    data = b"HTTP/1.1 200 OK\r\n" + padding * (count + 5) + b"Server: beyond\r\n\r\n"
    assert parse_http_head(data) == HttpHead(200, None)


def test_a_long_server_header_is_cut_to_the_character_cap() -> None:
    head = parse_http_head(b"HTTP/1.1 200 OK\r\nServer: " + b"s" * 900 + b"\r\n\r\n")
    assert head is not None
    assert head.server is not None
    assert (len(head.server), head.server.endswith("...")) == (MAX_HTTP_SERVER_CHARS, True)


# -- the request -----------------------------------------------------------------------------


def test_the_request_is_one_fixed_head_request() -> None:
    assert build_head_request("lab.test:80", "1.2.3") == (
        b"HEAD / HTTP/1.1\r\nHost: lab.test:80\r\nUser-Agent: network-scanner/1.2.3\r\n"
        b"Accept: */*\r\nConnection: close\r\n\r\n"
    )


@pytest.mark.parametrize("version", ["bad version", "1.0\r\nX-Evil: 1", "", "v" * 33, "caf\u00e9"])
def test_an_unexpected_tool_version_is_not_put_into_the_request(version: str) -> None:
    request = build_head_request("h:1", version)
    assert b"network-scanner/unknown\r\n" in request
    assert request.count(b"\r\n") == 6


@pytest.mark.parametrize(
    ("address", "port", "hostname", "expected"),
    [
        ("127.0.0.1", 80, None, "127.0.0.1:80"),
        ("::1", 8080, None, "[::1]:8080"),
        ("fe80::1%eth0", 80, None, "[fe80::1]:80"),
        ("10.0.0.5", 443, "lab.test", "lab.test:443"),
        ("::1", 80, "lab.test", "lab.test:80"),
    ],
)
def test_the_host_header_is_the_name_or_the_address_literal(
    address: str, port: int, hostname: str | None, expected: str
) -> None:
    assert host_header(address, port, hostname=hostname) == expected


@pytest.mark.parametrize(
    "bad", ["", "a b", "a\r\nX: y", "a\x00", "caf\u00e9.test", "a/b", "a" * 254]
)
def test_a_host_that_cannot_be_sent_safely_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="not in a form"):
        host_header("10.0.0.5", 80, hostname=bad)
    with pytest.raises(ValueError, match="not in a form"):
        host_header(bad, 80, hostname=None)


# -- the HEAD exchange -----------------------------------------------------------------------


def head_of(stream: ScriptedStream, *, deadline: float = DEADLINE) -> tuple[HttpHead | None, float]:
    async def main() -> tuple[HttpHead | None, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await http_head(stream, request=b"REQUEST", deadline_s=deadline)
        return result, loop.time() - started

    return run_virtual(main)


def test_the_request_is_sent_once_and_the_head_is_read() -> None:
    stream = ScriptedStream([(0.0, OK)])
    result, elapsed = head_of(stream)
    assert result == HttpHead(200, "nginx/1.25")
    assert stream.written == [b"REQUEST"]
    assert elapsed == 0.0


def test_a_head_in_several_chunks_is_read_until_the_blank_line() -> None:
    chunks = [(0.1, OK[:10]), (0.1, OK[10:30]), (0.1, OK[30:]), (0.0, b"never read")]
    stream = ScriptedStream(chunks)
    result, _ = head_of(stream)
    assert result == HttpHead(200, "nginx/1.25")
    assert stream.delivered == len(OK)


def test_a_silent_service_gives_no_head_after_exactly_the_deadline() -> None:
    result, elapsed = head_of(ScriptedStream(hang=True))
    assert (result, elapsed) == (None, DEADLINE)


def test_an_endless_response_stops_at_the_head_cap() -> None:
    stream = ScriptedStream([(0.0, b"HTTP/1.1 200 OK\r\n")], endless=b"X-Pad: 1\r\n")
    result, elapsed = head_of(stream)
    assert result == HttpHead(200, None)
    assert stream.delivered == MAX_HTTP_HEAD_BYTES
    assert elapsed == 0.0


def test_an_endless_response_that_is_not_http_gives_nothing() -> None:
    stream = ScriptedStream(endless=b"\x00\x01garbage")
    result, _ = head_of(stream)
    assert result is None
    assert stream.delivered == MAX_HTTP_HEAD_BYTES


def test_a_slow_drip_response_runs_out_of_time() -> None:
    drip = [(0.5, byte.to_bytes(1, "big")) for byte in b"HTTP/1.1 200 OK\r\nServer: slow\r\n\r\n"]
    result, elapsed = head_of(ScriptedStream(drip))
    assert elapsed == DEADLINE
    assert result is None  # four bytes arrived; the status line never completed


def test_a_status_line_that_arrived_before_the_deadline_still_counts() -> None:
    chunks = [(0.0, b"HTTP/1.1 503 Busy\r\n"), (5.0, b"Server: too-late\r\n\r\n")]
    result, elapsed = head_of(ScriptedStream(chunks))
    assert (result, elapsed) == (HttpHead(503, None), DEADLINE)


def test_a_reset_while_writing_gives_no_head() -> None:
    stream = ScriptedStream([(0.0, OK)], write_error=NetErrorCode.RESET)
    assert head_of(stream)[0] is None
    assert stream.written == []


def test_a_reset_while_reading_gives_no_head() -> None:
    assert head_of(ScriptedStream(read_error=NetErrorCode.RESET))[0] is None
