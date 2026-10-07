from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import pytest

import measure_connect
from network_scanner.core.limits import DEFAULT_LIMITS

pytestmark = pytest.mark.leakcheck


def test_summarise_reports_milliseconds_rounded_to_a_tenth() -> None:
    assert measure_connect.summarise([0.001, 0.002, 0.0100004]) == {
        "samples": 3,
        "min_ms": 1.0,
        "median_ms": 2.0,
        "max_ms": 10.0,
    }


def test_only_the_two_loopback_addresses_can_be_measured() -> None:
    assert measure_connect.LOOPBACK_HOSTS == ("127.0.0.1", "::1")
    for host in ("8.8.8.8", "0.0.0.0", "192.168.1.1", "localhost", "127.0.0.2", ""):
        with pytest.raises(ValueError, match="loopback"):
            asyncio.run(measure_connect.measure(hosts=(host,), samples=1, concurrent=1))


def test_a_real_measurement_has_the_documented_shape() -> None:
    result = asyncio.run(measure_connect.measure(hosts=("127.0.0.1",), samples=1, concurrent=2))
    assert result["default_connect_timeout_s"] == DEFAULT_LIMITS.connect_timeout_s
    assert result["event_loop"].endswith("EventLoop")
    host = result["hosts"]["127.0.0.1"]
    assert host["open"]["outcomes"] == ["open"]
    assert all(o.startswith("ConnectionRefusedError") for o in host["closed"]["outcomes"])
    assert all(
        o.startswith("ConnectionRefusedError") for o in host["closed_concurrent"]["outcomes"]
    )
    assert host["closed_concurrent"]["connects"] == 2
    assert result["slowest_refusal_ms"] == host["closed"]["max_ms"]
    json.dumps(result)  # serialisable


def test_a_host_that_cannot_be_bound_is_reported_as_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def cannot_bind(host: str, *, listen: bool) -> Any:
        raise OSError("no such address")

    monkeypatch.setattr(measure_connect, "_bound_socket", cannot_bind)
    result = asyncio.run(measure_connect.measure(hosts=("::1",), samples=1, concurrent=1))
    assert result["hosts"]["::1"] == {"skipped": "cannot bind ::1 here (OSError)"}
    assert result["slowest_refusal_ms"] is None


def test_main_prints_the_result_as_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fake(**kwargs: Any) -> dict[str, Any]:
        return {"samples": kwargs["samples"], "concurrent": kwargs["concurrent"]}

    monkeypatch.setattr(measure_connect, "measure", fake)
    assert measure_connect.main(["--samples", "3", "--concurrent", "5"]) == 0
    assert json.loads(capsys.readouterr().out) == {"samples": 3, "concurrent": 5}


@pytest.mark.parametrize(
    "args",
    [["--samples", "0"], ["--samples", "101"], ["--concurrent", "0"], ["--concurrent", "257"]],
)
def test_main_rejects_out_of_range_arguments(args: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        measure_connect.main(args)
    assert caught.value.code == 2


def test_a_socket_that_fails_to_bind_is_closed_not_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[socket.socket] = []

    class FailingSocket(socket.socket):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            created.append(self)

        def bind(self, address: Any) -> None:
            raise OSError("synthetic bind failure")

    monkeypatch.setattr(socket, "socket", FailingSocket)
    with pytest.raises(OSError, match="synthetic"):
        measure_connect._bound_socket("127.0.0.1", listen=False)
    assert [sock.fileno() for sock in created] == [-1]
