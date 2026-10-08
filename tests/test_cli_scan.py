from __future__ import annotations

import asyncio
import io
import json
import pathlib
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from fakes import Behaviour, FakeResolver, LoopClock, ScriptedConnector
from network_scanner import __version__
from network_scanner.cli.commands import scan as scan_module
from network_scanner.cli.environment import Environment
from network_scanner.cli.main import main
from network_scanner.core.errors import ResolutionError
from network_scanner.core.interfaces import Connection
from network_scanner.core.limits import DEFAULT_LIMITS
from network_scanner.core.model import SCHEMA_VERSION, ScanReport
from network_scanner.engine.scan import ScanOutcome, ScanStatus
from network_scanner.scope.policy import ScopeOptions

pytestmark = pytest.mark.leakcheck

STARTED = "2026-01-01T12:00:00+00:00"


class InstantSleeper:
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(0)


@dataclass
class Harness:
    env: Environment
    out: io.StringIO
    err: io.StringIO
    connector: ScriptedConnector
    asked: list[str] = field(default_factory=list)
    factory_options: list[ScopeOptions] = field(default_factory=list)

    def run(self, *argv: str) -> int:
        return main(list(argv), environment=self.env)


def harness(
    *,
    script: Callable[[str, int], Behaviour] | None = None,
    resolver: FakeResolver | None = None,
    interactive: bool = False,
    answers: list[str] | None = None,
    connector: ScriptedConnector | None = None,
) -> Harness:
    out, err = io.StringIO(), io.StringIO()
    shared = connector or ScriptedConnector(script)
    queue = list(answers or [])
    holder: dict[str, Harness] = {}

    def ask(prompt: str) -> str:
        holder["h"].asked.append(prompt)
        if not queue:
            raise EOFError
        return queue.pop(0)

    def factory(options: ScopeOptions) -> ScriptedConnector:
        holder["h"].factory_options.append(options)
        return shared

    env = Environment(
        stdout=out,
        stderr=err,
        interactive=interactive,
        ask=ask,
        resolver=resolver or FakeResolver(),
        clock=LoopClock(),
        sleeper=InstantSleeper(),
        connector_factory=factory,
    )
    holder["h"] = Harness(env, out, err, shared)
    return holder["h"]


def states_by_port(kinds: dict[int, str]) -> Callable[[str, int], Behaviour]:
    return lambda address, port: Behaviour(kinds[port])


# -- output and exit code 0 --------------------------------------------------------------------


def test_a_table_scan_prints_the_expected_report() -> None:
    h = harness(script=states_by_port({22: "open", 80: "refused", 443: "timeout"}))
    assert h.run("scan", "127.0.0.1", "--ports", "22,80,443") == 0
    assert h.out.getvalue() == (
        f"network-scanner {__version__}  started {STARTED}\n"
        "targets: 1  probes completed: 3\n"
        "\n"
        "ADDRESS    PORT  STATE\n"
        "127.0.0.1    22  open\n"
        "127.0.0.1   443  filtered (timeout)\n"
        "\n"
        "open: 1  closed: 1  filtered: 1  error: 0\n"
    )
    assert h.err.getvalue() == ""


def test_a_json_scan_prints_the_whole_report() -> None:
    h = harness(script=states_by_port({22: "open", 80: "refused"}))
    assert h.run("scan", "127.0.0.1", "10.0.0.5", "--ports", "22,80", "--format", "json") == 0
    data = json.loads(h.out.getvalue())
    assert data["tool_version"] == __version__
    assert data["started_at"] == STARTED
    assert data["complete"] is True
    assert [t["address"] for t in data["targets"]] == ["127.0.0.1", "10.0.0.5"]
    assert [(r["address"], r["port"], r["state"]) for r in data["results"]] == [
        ("127.0.0.1", 22, "open"),
        ("127.0.0.1", 80, "closed"),
        ("10.0.0.5", 22, "open"),
        ("10.0.0.5", 80, "closed"),
    ]


def test_the_default_ports_are_the_common_preset() -> None:
    h = harness()
    assert h.run("scan", "127.0.0.1", "--format", "json") == 0
    ports = [r["port"] for r in json.loads(h.out.getvalue())["results"]]
    assert ports[:3] == [21, 22, 23]
    assert len(ports) == len(set(ports)) > 30


def test_limit_flags_reach_the_run() -> None:
    h = harness(script=lambda address, port: Behaviour("open"))
    code = h.run(
        "scan", "127.0.0.1", "--ports", "1-6", "--concurrency", "2", "--rate", "50",
        "--connect-timeout", "1.5", "--total-timeout", "20", "--format", "json",
    )  # fmt: skip
    assert code == 0
    limits = json.loads(h.out.getvalue())["limits"]
    assert (limits["concurrency"], limits["connections_per_second"]) == (2, 50)
    assert (limits["connect_timeout_s"], limits["total_timeout_s"]) == (1.5, 20.0)
    assert h.connector.max_in_flight <= 2


def test_a_hostname_is_resolved_and_the_pinned_address_is_scanned() -> None:
    resolver = FakeResolver({"lab.example": ("10.0.0.5",)})
    h = harness(resolver=resolver)
    assert h.run("scan", "lab.example", "--ports", "22", "--format", "json") == 0
    data = json.loads(h.out.getvalue())
    assert data["targets"][0]["display_name"] == "lab.example"
    assert data["targets"][0]["address"] == "10.0.0.5"
    assert {a for a, _, _ in h.connector.attempts} == {"10.0.0.5"}  # never the name
    assert [name for name, _ in resolver.calls] == ["lab.example"]


# -- refusals: exit code 2, no connector, no output --------------------------------------------


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("169.254.169.254", "always_refused"),
        ("8.8.8.8", "public_not_allowed"),
        ("100.64.0.1", "public_not_allowed"),
        ("127.1", "ambiguous_numeric"),
        ("0x7f.0.0.1", "ambiguous_numeric"),
        ("::ffff:10.0.0.1", "embedded_ipv4"),
        ("10.0.0.0/8", "too_many_targets"),
        ("224.0.0.1", "always_refused"),
        ("192.168.1.5/24", "cidr_host_bits"),
        ("exa_mple.com", "invalid_hostname"),
        ("127.0.0.1\x00", "invalid_characters"),
        ("a" * 1_000_000, "target_too_long"),
        ("nowhere.example", "dns_failure"),
    ],
    ids=lambda v: repr(v)[:30],
)
def test_refused_targets_exit_2_with_the_reason_and_scan_nothing(target: str, reason: str) -> None:
    h = harness()
    assert h.run("scan", target) == 2
    assert h.out.getvalue() == ""
    assert h.err.getvalue().startswith(f"refused: {reason}: ")
    assert h.connector.attempts == []
    assert h.factory_options == []


def test_one_bad_target_among_good_ones_refuses_the_whole_run() -> None:
    h = harness()
    assert h.run("scan", "127.0.0.1", "10.0.0.1", "8.8.8.8", "--ports", "22") == 2
    assert h.connector.attempts == []


def test_a_refusal_never_echoes_control_characters() -> None:
    h = harness()
    assert h.run("scan", "\x1b[31m127.0.0.1\r\nevil") == 2
    assert not any(c in h.err.getvalue() for c in "\x1b\r")


def test_output_stays_ascii_even_for_a_stream_that_cannot_encode_anything_else() -> None:
    h = harness()
    stderr = io.TextIOWrapper(io.BytesIO(), encoding="ascii", write_through=True)
    env = Environment(**{**h.env.__dict__, "stderr": stderr})
    assert main(["scan", "b\u00fccher.example"], environment=env) == 2
    written = stderr.buffer.getvalue()
    assert written.isascii()
    assert b"invalid_hostname" in written


# -- the public-address gate -------------------------------------------------------------------


@pytest.fixture
def public_scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text("# test scope\n8.8.8.0/24\n", encoding="utf-8")
    return path


def test_public_targets_need_the_flag_and_the_scope_file(public_scope: Path) -> None:
    h = harness()
    assert h.run("scan", "8.8.8.8", "--allow-public") == 2
    assert "not_in_scope_file" in h.err.getvalue()
    h = harness()
    assert h.run("scan", "8.8.8.8", "--scope-file", str(public_scope)) == 2
    assert "public_not_allowed" in h.err.getvalue()


def test_without_a_terminal_public_targets_need_yes(public_scope: Path) -> None:
    args = ("scan", "8.8.8.8", "--ports", "53", "--allow-public", "--scope-file", str(public_scope))
    h = harness()
    assert h.run(*args) == 2
    assert "confirmation_required" in h.err.getvalue()
    assert h.asked == []
    h = harness()
    assert h.run(*args, "--yes") == 0
    assert h.asked == []
    assert [a for a, _, _ in h.connector.attempts] == ["8.8.8.8"]
    [options] = h.factory_options
    assert (options.allow_public, options.assume_yes) == (True, True)
    assert options.scope_file is not None


@pytest.mark.parametrize("answer", ["yes", " YES\n", "Yes"])
def test_typing_yes_at_the_prompt_allows_the_scan(public_scope: Path, answer: str) -> None:
    h = harness(interactive=True, answers=[answer])
    code = h.run(
        "scan", "8.8.8.8", "--ports", "53", "--allow-public", "--scope-file", str(public_scope)
    )
    assert code == 0
    assert len(h.asked) == 1
    assert "1 public address(es) will be scanned: 8.8.8.8" in h.err.getvalue()


@pytest.mark.parametrize("answers", [["y"], ["no"], [""], ["yes please"], []])
def test_anything_but_yes_at_the_prompt_declines(public_scope: Path, answers: list[str]) -> None:
    h = harness(interactive=True, answers=answers)
    code = h.run(
        "scan", "8.8.8.8", "--ports", "53", "--allow-public", "--scope-file", str(public_scope)
    )
    assert code == 2
    assert "confirmation_declined" in h.err.getvalue()
    assert h.connector.attempts == []


def test_the_prompt_lists_at_most_ten_addresses(public_scope: Path) -> None:
    h = harness(interactive=True, answers=["yes"])
    code = h.run(
        "scan", "8.8.8.0/28", "--ports", "53", "--allow-public", "--scope-file", str(public_scope)
    )
    assert code == 0
    assert "14 public address(es) will be scanned: 8.8.8.1, " in h.err.getvalue()
    assert "and 4 more" in h.err.getvalue()


def test_a_private_scan_never_prompts() -> None:
    h = harness(interactive=True, answers=[])
    assert h.run("scan", "10.0.0.1", "--ports", "22") == 0
    assert h.asked == []


# -- usage errors: ports, limits, hostile arguments --------------------------------------------


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["--ports", "0"], "invalid_port"),
        (["--ports", "22, 80"], "invalid_characters"),
        (["--ports", "1-70000"], "invalid_range"),
        (["--ports", "1-2000"], "too_many_ports"),
        (["--ports", ""], "empty_spec"),
        (["--ports", "nope"], "unknown_preset"),
        (["--concurrency", "0"], "concurrency must be"),
        (["--concurrency", "513"], "concurrency must be"),
        (["--rate", "1001"], "connections_per_second must be"),
        (["--connect-timeout", "31"], "connect_timeout_s must be"),
        (["--connect-timeout", "0"], "connect_timeout_s must be"),
        (["--total-timeout", "3601"], "total_timeout_s must be"),
    ],
)
def test_bad_ports_and_limits_exit_2_and_scan_nothing(args: list[str], fragment: str) -> None:
    h = harness()
    assert h.run("scan", "127.0.0.1", *args) == 2
    assert h.err.getvalue().startswith("error: ")
    assert fragment in h.err.getvalue()
    assert h.connector.attempts == []


@pytest.mark.parametrize(
    "args",
    [
        ["--concurrency", "abc"],
        ["--concurrency", "-1"],
        ["--concurrency", "1e3"],
        ["--concurrency", "1234567"],
        ["--concurrency", "\u0661\u0662"],
        ["--rate", ""],
        ["--connect-timeout", "nan"],
        ["--connect-timeout", "inf"],
        ["--connect-timeout", "1." + "9" * 50],
        ["--total-timeout", "-5"],
        ["--format", "xml"],
        ["--bogus"],
        ["--scope-file"],
    ],
    ids=lambda v: repr(v)[:40],
)
def test_malformed_options_are_rejected_by_the_parser(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    h = harness()
    assert h.run("scan", "127.0.0.1", *args) == 2
    assert capsys.readouterr().err.startswith("usage: ")
    assert h.connector.attempts == []


def test_scan_without_targets_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert harness().run("scan") == 2
    assert "required" in capsys.readouterr().err


def test_parser_errors_do_not_echo_raw_control_characters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert harness().run("scan", "127.0.0.1", "--bogus\x1b[31m\r\nx") == 2
    assert not any(c in capsys.readouterr().err for c in "\x1b\r")


@pytest.mark.parametrize(
    "path",
    [
        "\\\\server\\share\\scope.txt",
        "//server/share/scope.txt",
        "\\\\?\\C:\\scope.txt",
        "\\\\.\\pipe\\x",
        "\\/server/share",
        "/\\server\\share",
        "file:///etc/scope",
        "https://example.com/scope.txt",
        "scope\x00.txt",
        "a" * 5000,
    ],
    ids=lambda v: repr(v)[:30],
)
def test_network_device_and_url_paths_are_refused_before_anything_is_opened(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a file was opened for a refused path")

    monkeypatch.setattr(pathlib.Path, "open", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    h = harness()
    assert h.run("scan", "127.0.0.1", "--scope-file", path) == 2
    assert "scope-file" in capsys.readouterr().err
    assert h.connector.attempts == []


def test_a_missing_or_invalid_scope_file_is_a_usage_error(tmp_path: Path) -> None:
    h = harness()
    assert h.run("scan", "127.0.0.1", "--scope-file", str(tmp_path / "missing.txt")) == 2
    assert h.err.getvalue().startswith("error: cannot read the scope file")
    bad = tmp_path / "bad.txt"
    bad.write_text("example.com\n", encoding="utf-8")
    h = harness()
    assert h.run("scan", "127.0.0.1", "--scope-file", str(bad)) == 2
    assert "line 1: only IP addresses and CIDR" in h.err.getvalue()


def test_too_many_probes_are_refused_before_any_connection() -> None:
    h = harness()
    assert h.run("scan", "10.0.0.0/24", "--ports", "1-1024") == 2
    assert "more than 100000 probes" in h.err.getvalue()
    assert h.connector.attempts == []


def test_scan_help_and_the_top_level_help_mention_the_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--help"]) == 0
    assert "scan" in capsys.readouterr().out
    assert main(["scan", "--help"]) == 0
    out = " ".join(capsys.readouterr().out.split()).lower()
    assert "unauthorized scanning can be illegal" in out
    assert "--allow-public" in out


# -- exit codes for the other outcomes ---------------------------------------------------------


def outcome_with(status: ScanStatus) -> Callable[..., Any]:
    report = ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        started_at=STARTED,
        complete=status is ScanStatus.COMPLETED,
        probed=False,
        limits=DEFAULT_LIMITS,
        targets=(),
        results=(),
        observations=(),
        findings=(),
    )

    async def fake_scan(*args: Any, **kwargs: Any) -> ScanOutcome:
        return ScanOutcome(report, status)

    return fake_scan


@pytest.mark.parametrize(
    ("status", "code", "message"),
    [
        (ScanStatus.COMPLETED, 0, ""),
        (ScanStatus.INTERRUPTED, 130, "interrupted: the report above is partial"),
        (ScanStatus.TIMED_OUT, 3, "total timeout was reached"),
    ],
)
def test_the_scan_status_decides_the_exit_code_and_the_report_is_still_printed(
    monkeypatch: pytest.MonkeyPatch, status: ScanStatus, code: int, message: str
) -> None:
    monkeypatch.setattr(scan_module, "_scan", outcome_with(status))
    h = harness()
    assert h.run("scan", "127.0.0.1", "--ports", "22") == code
    assert "network-scanner" in h.out.getvalue()
    assert message in h.err.getvalue()


def test_unexpected_errors_exit_3_without_a_traceback_or_control_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*args: Any, **kwargs: Any) -> ScanOutcome:
        raise RuntimeError("boom\x1b[31m\r\nsecond line")

    monkeypatch.setattr(scan_module, "_scan", boom)
    h = harness()
    assert h.run("scan", "127.0.0.1", "--ports", "22") == 3
    assert h.err.getvalue().startswith("internal error: RuntimeError: boom")
    assert "Traceback" not in h.err.getvalue()
    assert not any(c in h.err.getvalue() for c in "\x1b\r")


def test_our_own_runtime_errors_exit_3(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing(*args: Any, **kwargs: Any) -> ScanOutcome:
        raise ResolutionError("the resolver is broken")

    monkeypatch.setattr(scan_module, "_scan", failing)
    h = harness()
    assert h.run("scan", "127.0.0.1", "--ports", "22") == 3
    assert h.err.getvalue() == "error: the resolver is broken\n"


def test_ctrl_c_before_the_scan_starts_exits_130() -> None:
    h = harness(resolver=FakeResolver({"slow.example": KeyboardInterrupt()}))
    assert h.run("scan", "slow.example") == 130
    assert h.err.getvalue() == "interrupted before the scan started\n"
    assert h.out.getvalue() == ""


class InterruptingConnector:
    """Opens the first port, then delivers a real SIGINT to this process on the second."""

    def __init__(self) -> None:
        self.calls = 0

    async def connect(self, address: str, port: int, *, timeout: float) -> Connection:
        self.calls += 1
        if self.calls == 2:
            signal.raise_signal(signal.SIGINT)
            await asyncio.sleep(3600)  # the SIGINT handler cancels this task first
        return ScriptedConnectorConnection()


class ScriptedConnectorConnection:
    async def read(self, max_bytes: int, *, timeout: float) -> bytes:
        return b""

    async def write(self, data: bytes) -> None:
        return None

    async def close(self) -> None:
        return None


def test_a_real_ctrl_c_during_the_scan_prints_the_partial_report_and_exits_130() -> None:
    if signal.getsignal(signal.SIGINT) is not signal.default_int_handler:
        pytest.skip("another SIGINT handler is installed; not raising a real signal")
    connector = InterruptingConnector()
    h = harness()
    h.env = Environment(**{**h.env.__dict__, "connector_factory": lambda options: connector})
    code = h.run(
        "scan", "127.0.0.1", "--ports", "1,2,3,4", "--concurrency", "1", "--format", "json"
    )
    assert code == 130
    assert connector.calls == 2  # nothing was attempted after the interrupt
    data = json.loads(h.out.getvalue())
    assert data["complete"] is False
    assert [(r["port"], r["state"]) for r in data["results"]] == [(1, "open")]
    assert h.err.getvalue() == "interrupted: the report above is partial\n"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler  # restored
