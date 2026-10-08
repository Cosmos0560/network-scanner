"""`scan` with fingerprints and findings, `--output`, `baseline save` and `diff`, and `demo`.

Most tests drive the real argument parser and pipeline with scripted streams and a scripted
TLS prober (no sockets). The demo tests run the real lab on loopback.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeResolver, LoopClock
from network_scanner.baseline.store import BASELINE_KIND
from network_scanner.cli import pipeline as pipeline_module
from network_scanner.cli.environment import Environment, default_environment
from network_scanner.cli.main import main
from network_scanner.engine.scan import ScanOutcome, ScanStatus
from probe_fakes import FakeTlsProber, ScriptedStream, StreamConnector, tls_info

pytestmark = pytest.mark.leakcheck

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"
Step = ScriptedStream | BaseException | str


class InstantSleeper:
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(0)


def opened(*after: Step) -> list[Step]:
    """An open port: the scan's own connection, then the probes' connections."""
    return [ScriptedStream(), *after]


def lab_plan(*, ssh_banner: bytes = SSH_BANNER, telnet: bool = True) -> dict[int, list[Step]]:
    plan: dict[int, list[Step]] = {
        22: opened(ScriptedStream([(0.0, ssh_banner)])),
        80: opened(
            ScriptedStream(),
            ScriptedStream([(0.0, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")]),
        ),
        443: opened(ScriptedStream()),  # silent, then the TLS prober answers
    }
    if telnet:
        plan[23] = opened(ScriptedStream([(0.0, b"Debian GNU/Linux\r\nlogin: ")]))
    return plan


@dataclass
class Harness:
    env: Environment
    out: io.StringIO
    err: io.StringIO
    connector: StreamConnector

    def run(self, *argv: str) -> int:
        return main(list(argv), environment=self.env)


def harness(plan: dict[int, list[Step]] | None = None) -> Harness:
    out, err = io.StringIO(), io.StringIO()
    connector = StreamConnector(plan if plan is not None else lab_plan())
    env = Environment(
        stdout=out,
        stderr=err,
        interactive=False,
        ask=input,
        resolver=FakeResolver(),
        clock=LoopClock(),
        sleeper=InstantSleeper(),
        connector_factory=lambda options: connector,
        tls_prober_factory=lambda options, clock: FakeTlsProber(tls_info()),
    )
    return Harness(env, out, err, connector)


SCAN = ("scan", "127.0.0.1", "--ports", "22,23,80,443,9", "--rate", "1000")


# -- scan with fingerprints and findings, in every format -------------------------------------


def test_the_table_shows_services_details_and_findings() -> None:
    h = harness()
    assert h.run(*SCAN) == 0
    text = h.out.getvalue()
    lines = text.splitlines()
    assert lines[3].split() == ["ADDRESS", "PORT", "STATE", "SERVICE"]
    services = {int(line.split()[1]): " ".join(line.split()[3:]) for line in lines[4:8]}
    assert services == {22: "ssh (high)", 23: "telnet (low)", 80: "http (high)", 443: "tls (high)"}
    assert "PORT DETAILS" in text
    assert "  banner: SSH-2.0-OpenSSH_9.6\n" in text
    assert "  http: status 200, server nginx\n" in text
    assert "[medium/low] cleartext-telnet 127.0.0.1:23 - " in text
    assert "[info/high] tls-certificate-self-issued 127.0.0.1:443 - " in text
    assert text.endswith(
        "open: 4  closed: 1  filtered: 0  error: 0\nfindings: 2 (medium: 1, info: 1)\n"
    )
    assert h.err.getvalue() == ""


def test_json_has_services_observations_and_findings() -> None:
    h = harness()
    assert h.run(*SCAN, "--format", "json") == 0
    data = json.loads(h.out.getvalue())
    assert data["probed"] is True
    assert {o["port"]: o["service"]["name"] for o in data["observations"]} == {
        22: "ssh",
        23: "telnet",
        80: "http",
        443: "tls",
    }
    assert {f["id"] for f in data["findings"]} == {
        "cleartext-telnet",
        "tls-certificate-self-issued",
    }
    telnet = next(f for f in data["findings"] if f["id"] == "cleartext-telnet")
    assert (telnet["severity"], telnet["confidence"]) == ("medium", "low")
    assert telnet["evidence"].startswith("127.0.0.1:23 looks like telnet")
    assert telnet["references"] == ["CWE-319", "RFC 854"]


def test_jsonl_and_csv_carry_the_same_facts() -> None:
    h = harness()
    assert h.run(*SCAN, "--format", "jsonl") == 0
    objects = [json.loads(line) for line in h.out.getvalue().splitlines()]
    assert [o["type"] for o in objects].count("observation") == 4
    assert [o["id"] for o in objects if o["type"] == "finding"] == [
        "cleartext-telnet",
        "tls-certificate-self-issued",
    ]

    h = harness()
    assert h.run(*SCAN, "--format", "csv") == 0
    rows = list(csv.DictReader(io.StringIO(h.out.getvalue(), newline="")))
    ports = {r["port"]: r for r in rows if r["record"] == "port"}
    assert ports["22"]["service"] == "ssh"
    assert ports["443"]["tls_self_issued"] == "true"
    assert ports["9"]["state"] == "closed"
    assert [r["finding_id"] for r in rows if r["record"] == "finding"] == [
        "cleartext-telnet",
        "tls-certificate-self-issued",
    ]


def test_connect_only_sends_nothing_after_connecting() -> None:
    h = harness()
    assert h.run(*SCAN, "--connect-only", "--format", "json") == 0
    data = json.loads(h.out.getvalue())
    assert data["probed"] is False
    assert data["observations"] == []
    assert data["findings"] == []
    assert len(h.connector.connects) == 5  # one connect per port, no probe connections
    assert all(stream.written == [] for stream in h.connector.streams)


def test_the_probes_use_the_connector_and_at_most_three_connections_per_port() -> None:
    h = harness()
    assert h.run(*SCAN) == 0
    per_port = {
        port: sum(1 for _, p in h.connector.connects if p == port) for port in (22, 23, 80, 443)
    }
    assert per_port == {22: 2, 23: 2, 80: 3, 443: 2}  # the scan's own connection plus the probes
    assert all(address == "127.0.0.1" for address, _ in h.connector.connects)


# -- --fail-on ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("threshold", "code"),
    [("info", 1), ("low", 1), ("medium", 1), ("high", 0), ("critical", 0)],
)
def test_fail_on_exits_one_when_a_finding_reaches_the_severity(threshold: str, code: int) -> None:
    h = harness()
    assert h.run(*SCAN, "--fail-on", threshold) == code
    assert "cleartext-telnet" in h.out.getvalue()  # the report is printed either way


def test_without_fail_on_findings_do_not_change_the_exit_code() -> None:
    assert harness().run(*SCAN) == 0


def test_fail_on_with_nothing_found_is_clean() -> None:
    h = harness(lab_plan(telnet=False))
    assert h.run("scan", "127.0.0.1", "--ports", "22", "--rate", "1000", "--fail-on", "info") == 0


def test_an_unknown_fail_on_severity_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert harness().run(*SCAN, "--fail-on", "urgent") == 2
    assert "invalid choice" in capsys.readouterr().err


def test_a_partial_scan_keeps_its_own_exit_code_over_fail_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = harness()
    real = pipeline_module.scan_prepared

    async def interrupted(*args: Any, **kwargs: Any) -> ScanOutcome:
        outcome = await real(*args, **kwargs)
        return ScanOutcome(outcome.report, ScanStatus.INTERRUPTED, outcome.observations)

    monkeypatch.setattr(pipeline_module, "scan_prepared", interrupted)
    assert h.run(*SCAN, "--fail-on", "info") == 130
    assert "interrupted" in h.err.getvalue()
    assert "cleartext-telnet" in h.out.getvalue()


# -- --output -------------------------------------------------------------------------------


def test_output_writes_the_report_to_a_new_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    h = harness()
    assert h.run(*SCAN, "--format", "json", "--output", str(target)) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["probed"] is True
    assert h.out.getvalue() == f"report written to {target.as_posix()}\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.json"]


def test_output_refuses_an_existing_file_before_scanning_and_force_replaces_it(
    tmp_path: Path,
) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")
    h = harness()
    assert h.run(*SCAN, "--output", str(target)) == 2
    assert "already exists; use --force" in h.err.getvalue()
    assert h.connector.connects == []  # it failed before any connection
    assert target.read_text(encoding="utf-8") == "original"

    h = harness()
    assert h.run(*SCAN, "--output", str(target), "--force") == 0
    assert target.read_text(encoding="utf-8").startswith("network-scanner ")


@pytest.mark.parametrize(
    "bad",
    ["//server/share/out.json", "\\\\server\\share\\out.json", "https://example.test/x", "\x00"],
    ids=["unc-slash", "unc-backslash", "url", "nul"],
)
def test_output_refuses_unc_url_and_nul_paths(bad: str, capsys: pytest.CaptureFixture[str]) -> None:
    h = harness()
    assert h.run(*SCAN, "--output", bad) == 2
    assert capsys.readouterr().err
    assert h.connector.connects == []


@pytest.mark.parametrize("bad", ["NUL", "con.txt", "/dev/null", "/proc/self/x"])
def test_output_refuses_device_paths(bad: str) -> None:
    h = harness()
    assert h.run(*SCAN, "--output", bad) == 2
    assert "not accepted" in h.err.getvalue()
    assert h.connector.connects == []


def test_output_into_a_missing_directory_is_refused(tmp_path: Path) -> None:
    h = harness()
    assert h.run(*SCAN, "--output", str(tmp_path / "nope" / "r.json")) == 2
    assert "directory does not exist" in h.err.getvalue()


# -- baseline save and diff -----------------------------------------------------------------


def save(baseline: Path, plan: dict[int, list[Step]] | None = None) -> Harness:
    h = harness(plan)
    assert h.run("baseline", "save", *SCAN[1:], "--baseline", str(baseline)) == 0
    return h


def test_baseline_save_writes_the_open_ports_and_their_services(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    h = save(path)
    assert h.out.getvalue() == f"baseline saved: 4 open port(s) -> {path.as_posix()}\n"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["kind"] == BASELINE_KIND
    assert data["schema_version"] == 1
    assert [(e["address"], e["port"], e["service"]) for e in data["entries"]] == [
        ("127.0.0.1", 22, "ssh"),
        ("127.0.0.1", 23, "telnet"),
        ("127.0.0.1", 80, "http"),
        ("127.0.0.1", 443, "tls"),
    ]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["baseline.json"]


def test_baseline_save_will_not_replace_a_file_without_force(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("keep me", encoding="utf-8")
    h = harness()
    assert h.run("baseline", "save", *SCAN[1:], "--baseline", str(path)) == 2
    assert "already exists; use --force" in h.err.getvalue()
    assert h.connector.connects == []
    assert path.read_text(encoding="utf-8") == "keep me"
    h = harness()
    assert h.run("baseline", "save", *SCAN[1:], "--baseline", str(path), "--force") == 0
    assert json.loads(path.read_text(encoding="utf-8"))["kind"] == BASELINE_KIND


def diff(baseline: Path, plan: dict[int, list[Step]], *extra: str) -> Harness:
    h = harness(plan)
    h.code = h.run("baseline", "diff", *SCAN[1:], "--baseline", str(baseline), *extra)  # type: ignore[attr-defined]
    return h


def test_an_unchanged_network_has_no_drift(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    h = diff(path, lab_plan())
    assert h.code == 0  # type: ignore[attr-defined]
    assert h.out.getvalue().splitlines()[0] == "baseline diff: no drift"
    assert "findings in this scan: 2 (medium: 1, info: 1)" in h.out.getvalue()


def test_new_closed_and_changed_ports_are_drift_with_exit_code_one(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    plan = lab_plan(telnet=False)  # 23 is closed now
    plan[22] = opened(ScriptedStream([(0.0, b"220 ProFTPD FTP server ready\r\n")]))  # 22 is ftp
    plan[9] = opened(ScriptedStream([(0.0, SSH_BANNER)]))  # port 9 is new (and ssh)
    h = diff(path, plan)
    assert h.code == 1  # type: ignore[attr-defined]
    assert h.out.getvalue().splitlines()[:2] == [
        "baseline diff: drift found",
        "new: 1  closed: 1  changed: 1  not scanned: 0",
    ]
    assert "NEW          127.0.0.1:9 (ssh)\n" in h.out.getvalue()
    assert "CLOSED       127.0.0.1:23 (telnet)\n" in h.out.getvalue()
    assert "CHANGED      127.0.0.1:22 ssh -> ftp\n" in h.out.getvalue()


def test_drift_as_json(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    h = diff(path, lab_plan(telnet=False), "--format", "json")
    data = json.loads(h.out.getvalue())
    assert h.code == 1  # type: ignore[attr-defined]
    assert data["has_drift"] is True
    assert data["drift"]["closed"] == [{"address": "127.0.0.1", "port": 23, "service": "telnet"}]


def test_a_narrower_scan_reports_entries_it_did_not_cover_without_calling_them_drift(
    tmp_path: Path,
) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    h = harness({22: opened(ScriptedStream([(0.0, SSH_BANNER)]))})
    assert h.run("baseline", "diff", "127.0.0.1", "--ports", "22", "--baseline", str(path)) == 0
    assert "not scanned: 3" in h.out.getvalue()
    assert "NOT SCANNED  127.0.0.1:80 (http)" in h.out.getvalue()


def test_drift_wins_the_exit_code_and_fail_on_adds_to_it(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    assert diff(path, lab_plan(), "--fail-on", "high").code == 0  # type: ignore[attr-defined]
    assert diff(path, lab_plan(), "--fail-on", "medium").code == 1  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b'{"schema_version": 99}', b"[1]", b"\xff\xfe", b"x" * 100],
    ids=["empty", "text", "newer", "array", "binary", "junk"],
)
def test_a_bad_baseline_file_fails_with_exit_code_two_before_any_connection(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "baseline.json"
    path.write_bytes(content)
    h = harness()
    assert h.run("baseline", "diff", *SCAN[1:], "--baseline", str(path)) == 2
    assert h.err.getvalue().startswith("error: ")
    assert h.connector.connects == []


def test_a_missing_baseline_file_is_exit_code_two(tmp_path: Path) -> None:
    h = harness()
    assert h.run("baseline", "diff", *SCAN[1:], "--baseline", str(tmp_path / "none.json")) == 2
    assert "cannot read the baseline file" in h.err.getvalue()


@pytest.mark.parametrize(
    ("status", "code", "message"),
    [
        (ScanStatus.INTERRUPTED, 130, "interrupted: no baseline was written"),
        (ScanStatus.TIMED_OUT, 3, "total timeout was reached: no baseline was written"),
    ],
)
def test_an_incomplete_scan_writes_no_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: ScanStatus,
    code: int,
    message: str,
) -> None:
    real = pipeline_module.scan_prepared

    async def partial(*args: Any, **kwargs: Any) -> ScanOutcome:
        outcome = await real(*args, **kwargs)
        return ScanOutcome(outcome.report, status, outcome.observations)

    monkeypatch.setattr(pipeline_module, "scan_prepared", partial)
    path = tmp_path / "baseline.json"
    h = harness()
    assert h.run("baseline", "save", *SCAN[1:], "--baseline", str(path)) == code
    assert message in h.err.getvalue()
    assert not path.exists()


def test_an_incomplete_scan_gives_no_drift_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    real = pipeline_module.scan_prepared

    async def partial(*args: Any, **kwargs: Any) -> ScanOutcome:
        outcome = await real(*args, **kwargs)
        return ScanOutcome(outcome.report, ScanStatus.INTERRUPTED, outcome.observations)

    monkeypatch.setattr(pipeline_module, "scan_prepared", partial)
    h = harness()
    assert h.run("baseline", "diff", *SCAN[1:], "--baseline", str(path)) == 130
    assert h.out.getvalue() == ""
    assert "no drift was computed" in h.err.getvalue()


def test_baseline_without_an_action_is_a_usage_error() -> None:
    h = harness()
    assert h.run("baseline") == 2
    assert "choose an action" in h.err.getvalue()


def test_baseline_save_needs_a_baseline_option(capsys: pytest.CaptureFixture[str]) -> None:
    assert harness().run("baseline", "save", "127.0.0.1") == 2
    assert "--baseline" in capsys.readouterr().err


def test_a_scope_refusal_in_baseline_diff_is_exit_code_two(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save(path)
    h = harness()
    assert h.run("baseline", "diff", "8.8.8.8", "--baseline", str(path)) == 2
    assert h.err.getvalue().startswith("refused: public_not_allowed")
    assert h.connector.connects == []


# -- the demo -------------------------------------------------------------------------------


def run_demo(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    base = default_environment()
    env = Environment(**{**base.__dict__, "stdout": out, "stderr": err})
    code = main(["demo", *argv], environment=env)
    return code, out.getvalue(), err.getvalue()


@dataclass
class DemoRun:
    code: int
    out: str
    err: str
    connects: list[tuple[str, int]]


@pytest.fixture(scope="module")
def demo_json() -> DemoRun:
    """One real demo run, shared by the tests that look at its JSON report."""
    from network_scanner.net.connector import AsyncioConnector

    seen: list[tuple[str, int]] = []
    real = AsyncioConnector.connect

    async def recording(self: AsyncioConnector, address: str, port: int, *, timeout: float) -> Any:
        seen.append((address, port))
        return await real(self, address, port, timeout=timeout)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(AsyncioConnector, "connect", recording)
        code, out, err = run_demo("--format", "json")
    return DemoRun(code, out, err, seen)


def test_the_demo_scans_its_own_lab_and_names_all_four_services(demo_json: DemoRun) -> None:
    data = json.loads(demo_json.out)
    assert (demo_json.code, demo_json.err) == (0, "")
    assert data["complete"] is True
    assert [t["address"] for t in data["targets"]] == ["127.0.0.1"]
    assert {r["address"] for r in data["results"]} == {"127.0.0.1"}
    assert [r["state"] for r in data["results"]] == ["open"] * 4
    ports = [r["port"] for r in data["results"]]
    assert ports == sorted(ports)
    services = {o["service"]["name"]: o["service"]["confidence"] for o in data["observations"]}
    assert services == {"ssh": "high", "telnet": "low", "http": "high", "tls": "high"}
    assert {f["id"] for f in data["findings"]} == {
        "cleartext-telnet",
        "tls-certificate-self-issued",
    }


def test_the_demo_connects_only_to_loopback_and_never_to_port_8080(demo_json: DemoRun) -> None:
    assert demo_json.connects
    assert {address for address, _ in demo_json.connects} == {"127.0.0.1"}
    assert all(port != 8080 for _, port in demo_json.connects)


def test_the_demo_table_report_is_the_real_scan_output_and_can_be_written_to_a_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "demo.txt"
    code, out, _ = run_demo("--output", str(path))
    assert code == 0
    assert out == f"report written to {path.as_posix()}\n"
    text = path.read_text(encoding="utf-8")
    assert "SERVICE" in text
    assert "ssh (high)" in text
    assert "[medium/low] cleartext-telnet" in text
    assert text.splitlines()[-1] == "findings: 2 (medium: 1, info: 1)"
    code, out, err = run_demo("--output", str(path))  # refused before the lab even starts
    assert (code, out) == (2, "")
    assert "already exists" in err


def test_the_demo_takes_no_target(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["8.8.8.8"], ["--ports", "22"], ["--allow-public"], ["127.0.0.1"]):
        code, out, _ = run_demo(*argv)
        assert code == 2
        assert out == ""
        assert "unrecognized arguments" in capsys.readouterr().err


def test_rules_validate_checks_finding_rule_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["rules", "validate", "--kind", "findings"]) == 0
    assert capsys.readouterr().out == "OK: built-in finding rules (7 rules)\n"
    bad = tmp_path / "findings.yaml"
    bad.write_text("schema_version: 1\nrules: []\n", encoding="utf-8")
    assert main(["rules", "validate", "--kind", "findings", str(bad)]) == 2
    assert "rules: invalid_value" in capsys.readouterr().err
    assert main(["rules", "validate", str(bad)]) == 2  # the same file as a fingerprint file
