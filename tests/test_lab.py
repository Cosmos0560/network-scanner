from __future__ import annotations

import socket
from typing import Any, ClassVar

import pytest

from network_scanner.lab.servers import MAX_LAB_PORTS, LabError, PlainLab

pytestmark = pytest.mark.leakcheck


def test_a_lab_has_the_requested_distinct_os_assigned_ports() -> None:
    with PlainLab(open_count=3, closed_count=2) as lab:
        assert lab.host == "127.0.0.1"
        assert len(lab.open_ports) == 3
        assert len(lab.closed_ports) == 2
        everything = [*lab.open_ports, *lab.closed_ports]
        assert len(set(everything)) == 5
        assert all(1024 <= port <= 65535 for port in everything)


def test_open_ports_accept_connections_and_closed_ports_refuse_them() -> None:
    with PlainLab(open_count=2, closed_count=1) as lab:
        for port in lab.open_ports:
            with socket.create_connection(("127.0.0.1", port), timeout=10):
                pass
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", lab.closed_ports[0]), timeout=10)


def test_the_lab_can_be_empty() -> None:
    with PlainLab(open_count=0, closed_count=0) as lab:
        assert lab.open_ports == () == lab.closed_ports


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "192.168.1.1", "10.0.0.1", "8.8.8.8", "localhost", "::", "127.0.0.2", ""]
)
def test_the_lab_binds_the_two_loopback_addresses_and_nothing_else(host: str) -> None:
    with pytest.raises(LabError, match="loopback"):
        PlainLab(host=host)


@pytest.mark.parametrize(("open_count", "closed_count"), [(-1, 0), (0, -1), (MAX_LAB_PORTS + 1, 0)])
def test_the_lab_size_is_bounded(open_count: int, closed_count: int) -> None:
    with pytest.raises(LabError, match="at most"):
        PlainLab(open_count=open_count, closed_count=closed_count)


def test_the_ports_are_released_and_forgotten_on_exit() -> None:
    lab = PlainLab(open_count=1, closed_count=1)
    with lab:
        assert lab.open_ports
    assert lab.open_ports == () == lab.closed_ports


class RecordingSocket(socket.socket):
    """Records every socket the lab creates and can fail the Nth bind."""

    created: ClassVar[list[RecordingSocket]] = []
    fail_on_bind = 0
    binds = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        RecordingSocket.created.append(self)

    def bind(self, address: Any) -> None:
        RecordingSocket.binds += 1
        if RecordingSocket.binds == RecordingSocket.fail_on_bind:
            raise OSError("synthetic bind failure")
        super().bind(address)


def test_a_failure_part_way_through_setup_closes_everything_opened_so_far(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    RecordingSocket.created = []
    RecordingSocket.binds = 0
    RecordingSocket.fail_on_bind = 4
    monkeypatch.setattr(socket, "socket", RecordingSocket)
    with pytest.raises(LabError, match="cannot bind"):
        PlainLab(open_count=3, closed_count=3).__enter__()
    assert len(RecordingSocket.created) == 4
    assert all(sock.fileno() == -1 for sock in RecordingSocket.created)


def test_a_machine_that_cannot_create_a_socket_gives_a_lab_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> socket.socket:
        raise OSError("no sockets")

    monkeypatch.setattr(socket, "socket", refuse)
    with pytest.raises(LabError, match="cannot create a socket"):
        PlainLab().__enter__()


def test_the_ipv6_lab_works_or_says_why_it_cannot() -> None:
    try:
        with PlainLab(host="::1", open_count=1, closed_count=1) as lab:
            socket.create_connection(("::1", lab.open_ports[0]), timeout=10).close()
    except LabError as error:
        pytest.skip(f"no IPv6 loopback on this machine: {error}")
