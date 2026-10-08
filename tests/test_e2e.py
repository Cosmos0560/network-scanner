"""End to end: the real CLI, the real connector and real loopback sockets.

Every listener is created by the test (through `PlainLab`) on an OS-assigned port and closed
afterwards. Connections go to 127.0.0.1, 127.0.0.2 and ::1 only. The connect timeout is set
far above what any loopback connect or refusal takes (Windows can need about two seconds to
report a refused connection), so a slow machine cannot turn "closed" into "filtered".
"""

from __future__ import annotations

import io
import json
from contextlib import ExitStack
from typing import Any

import pytest

from fakes import FakeResolver
from network_scanner.cli.environment import Environment, real_tls_prober
from network_scanner.cli.main import main
from network_scanner.lab.servers import LabError, PlainLab
from network_scanner.net.connector import AsyncioConnector
from network_scanner.net.system import AsyncioSleeper, SystemClock

pytestmark = pytest.mark.leakcheck


def real_environment() -> tuple[Environment, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    env = Environment(
        stdout=out,
        stderr=err,
        interactive=False,
        ask=input,
        resolver=FakeResolver(),  # no hostnames in these tests, so no DNS of any kind
        clock=SystemClock(),
        sleeper=AsyncioSleeper(),
        connector_factory=AsyncioConnector,
        tls_prober_factory=real_tls_prober,
    )
    return env, out, err


def scan_json(*argv: str) -> tuple[int, dict[str, Any], str]:
    env, out, err = real_environment()
    code = main(
        ["scan", *argv, "--format", "json", "--connect-timeout", "10", "--connect-only"],
        environment=env,
    )
    return code, json.loads(out.getvalue()), err.getvalue()


def test_the_lab_is_reported_with_exact_states_per_address() -> None:
    with PlainLab(open_count=2, closed_count=2) as lab:
        ports = sorted([*lab.open_ports, *lab.closed_ports])
        code, report, stderr = scan_json(
            "127.0.0.1", "127.0.0.2", "--ports", ",".join(map(str, ports))
        )

        assert code == 0
        assert stderr == ""
        assert report["complete"] is True
        got = [(r["address"], r["port"], r["state"], r["error_code"]) for r in report["results"]]
        expected = [
            ("127.0.0.1", port, "open" if port in lab.open_ports else "closed") for port in ports
        ] + [("127.0.0.2", port, "closed") for port in ports]  # nothing listens on .2
        assert got == [
            (address, port, state, None if state == "open" else "refused")
            for address, port, state in expected
        ]


def test_the_table_report_of_a_real_scan() -> None:
    with PlainLab(open_count=1, closed_count=1) as lab:
        env, out, err = real_environment()
        ports = f"{lab.open_ports[0]},{lab.closed_ports[0]}"
        code = main(
            ["scan", "127.0.0.1", "--ports", ports, "--connect-timeout", "10", "--connect-only"],
            environment=env,
        )
        lines = out.getvalue().splitlines()
        assert code == 0
        assert err.getvalue() == ""
        assert lines[1] == "targets: 1  probes completed: 2"
        assert lines[3].split() == ["ADDRESS", "PORT", "STATE"]
        assert lines[4].split() == ["127.0.0.1", str(lab.open_ports[0]), "open"]
        assert lines[-1] == "open: 1  closed: 1  filtered: 0  error: 0"
        assert str(lab.closed_ports[0]) not in "\n".join(
            lines[3:-2]
        )  # closed ports are counted only


def test_a_cidr_target_scans_each_host_once() -> None:
    with PlainLab(open_count=1, closed_count=0) as lab:
        code, report, _ = scan_json("127.0.0.0/30", "--ports", str(lab.open_ports[0]))
        assert code == 0
        assert [(r["address"], r["state"]) for r in report["results"]] == [
            ("127.0.0.1", "open"),
            ("127.0.0.2", "closed"),
        ]


def test_the_scan_works_over_ipv6_loopback_when_the_machine_has_it() -> None:
    with ExitStack() as stack:
        try:
            lab = stack.enter_context(PlainLab(host="::1", open_count=1, closed_count=1))
        except LabError as error:
            pytest.skip(f"no IPv6 loopback on this machine: {error}")
        ports = sorted([*lab.open_ports, *lab.closed_ports])
        code, report, _ = scan_json("::1", "--ports", ",".join(map(str, ports)))
        assert code == 0
        assert {(r["address"], r["port"]): r["state"] for r in report["results"]} == {
            ("::1", lab.open_ports[0]): "open",
            ("::1", lab.closed_ports[0]): "closed",
        }


def test_a_refused_target_opens_no_connection_at_all() -> None:
    with PlainLab(open_count=1, closed_count=0) as lab:
        env, out, err = real_environment()
        # 169.254.169.254 is never contacted: the plan refuses it before any socket exists.
        code = main(
            ["scan", "127.0.0.1", "169.254.169.254", "--ports", str(lab.open_ports[0])],
            environment=env,
        )
    assert code == 2
    assert out.getvalue() == ""
    assert err.getvalue().startswith("refused: always_refused: ")
