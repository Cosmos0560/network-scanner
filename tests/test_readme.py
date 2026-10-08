"""The README's claims, numbers and examples stay in step with the code and the tests.

Every row of the claim table must name evidence that exists: a linked file must be there, and a
test named in a row must be defined in one of the files that row links to. A renamed or deleted
test therefore breaks the build instead of leaving a claim that points at nothing.
"""

from __future__ import annotations

import re
import ssl
from pathlib import Path

import pytest

from network_scanner import __version__
from network_scanner.cli.main import main
from network_scanner.core.limits import DEFAULT_LIMITS, MAX_DNS_ANSWERS
from network_scanner.engine.probes import build_head_request
from network_scanner.net.tls import client_context

REPO_ROOT = Path(__file__).resolve().parent.parent
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
SQUASHED = " ".join(README.split())


def section(heading: str) -> str:
    """The text under a `## heading`, up to the next `## `."""
    return README.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]


def claim_rows() -> list[tuple[str, str]]:
    rows = []
    for line in section("Claims and evidence").split("\n"):
        if not line.startswith("| ") or line.startswith(("| Claim", "|---")):
            continue
        claim, evidence = (cell.strip() for cell in line.strip("|").split(" | ", 1))
        rows.append((claim, evidence))
    return rows


def test_the_claim_table_has_rows() -> None:
    assert len(claim_rows()) >= 20


@pytest.mark.parametrize(("claim", "evidence"), claim_rows(), ids=lambda cell: cell[:50])
def test_every_claim_names_evidence_that_exists(claim: str, evidence: str) -> None:
    targets = re.findall(r"\]\(([^)#\s]+)(?:#[^)\s]*)?\)", evidence)
    assert targets, f"no evidence is linked for: {claim}"
    linked = []
    for target in targets:
        path = REPO_ROOT / target
        assert path.exists(), f"{target} does not exist (claim: {claim})"
        linked.append(path)
    sources = "\n".join(path.read_text(encoding="utf-8") for path in linked if path.suffix == ".py")
    for name in re.findall(r"`(test_[a-z0-9_]+)`", evidence):
        assert re.search(rf"^(?:async )?def {name}\(", sources, flags=re.MULTILINE), (
            f"{name} is not defined in a file linked in the same row"
        )


def test_the_version_in_the_readme_is_the_package_version() -> None:
    assert f"network-scanner {__version__}" in README
    assert f"(`{__version__}`)" in README


def test_the_layer_diagram_matches_the_architecture_check() -> None:
    from check_architecture import LAYERS

    block = section("Architecture").split("```", 2)[1]
    shown: dict[str, int] = {}
    for line in block.split("\n"):
        match = re.match(r"^(\d)  ([a-z, ]+?)\s+- ", line)
        if match:
            for package in match.group(2).split(", "):
                shown[package] = int(match.group(1))
    assert shown == LAYERS


def test_the_head_request_in_the_readme_is_the_request_that_is_sent() -> None:
    block = README.split("```\n   HEAD / HTTP/1.1\n", 1)[1].split("```", 1)[0]
    shown = ["HEAD / HTTP/1.1", *(line.strip() for line in block.split("\n") if line.strip())]
    sent = build_head_request("<host>:<port>", __version__).decode("ascii")
    expected = sent.replace(f"network-scanner/{__version__}", "network-scanner/<version>")
    assert shown == [line for line in expected.split("\r\n") if line]


def test_the_numbers_in_what_the_scanner_sends_are_the_defaults() -> None:
    assert f"at most {DEFAULT_LIMITS.banner_max_bytes} bytes" in SQUASHED
    assert f"or when {DEFAULT_LIMITS.banner_timeout_s:g} seconds have passed" in SQUASHED
    assert f"(the banner deadline is {DEFAULT_LIMITS.banner_timeout_s:g} seconds)" in SQUASHED
    assert f"default connect timeout ({DEFAULT_LIMITS.connect_timeout_s:g} seconds)" in SQUASHED
    assert DEFAULT_LIMITS.probes_per_open_port == 3
    assert "At most three are made per open port" in SQUASHED
    assert "at most four connections" in SQUASHED


def test_the_tls_minimum_in_the_readme_is_the_one_the_prober_sets() -> None:
    assert client_context().minimum_version is ssl.TLSVersion.TLSv1_2
    assert "lowest version it offers (**TLS 1.2**)" in SQUASHED
    assert "**TLS 1.2 is the minimum offered.**" in SQUASHED


def test_the_readme_shows_the_real_rules_validate_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for argv in (["rules", "validate"], ["rules", "validate", "--kind", "findings"]):
        assert main(argv) == 0
        assert capsys.readouterr().out.strip() in README


def test_every_command_is_in_the_readme_command_table(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--help"]) == 0
    listing = capsys.readouterr().out.split("COMMAND", 1)[1].split("options:", 1)[0]
    commands = set(re.findall(r"^    ([a-z]+)\s", listing, flags=re.MULTILINE))
    assert commands == {"scan", "baseline", "demo", "rules"}
    table = section("Commands").split("### ", 1)[0]
    for command in commands:
        assert f"| `network-scanner {command}" in table
    assert "baseline save" in table
    assert "baseline diff" in table


def test_the_readme_carries_the_legal_notice_and_the_roadmap() -> None:
    assert "Scan only networks you own or have written permission to scan." in SQUASHED
    assert "Unauthorized scanning can be illegal." in SQUASHED
    roadmap = " ".join(section("Roadmap").split())
    for item in ("UDP scanning", "OS fingerprinting", "credential testing", "CVE matching"):
        assert item in roadmap or item.replace("CVE", "vulnerability or CVE") in roadmap


def test_the_limitations_section_covers_the_required_points() -> None:
    text = " ".join(section("Limitations").split())
    for phrase in (
        "TCP connect only",
        "TLS 1.2 is the minimum offered",
        "Only the leaf certificate is read",
        "Reading a certificate is not validating it",
        "compares service names only",
        "check-then-rename race on POSIX",
        "DNS is resolved once and pinned",
        "no OS fingerprinting",
        "no CVE",
        "no credential testing",
    ):
        assert phrase in text, phrase


def test_the_limits_quoted_in_the_readme_are_the_command_line_limits() -> None:
    text = " ".join(section("Limitations").split())
    assert (
        f"at most {DEFAULT_LIMITS.max_targets} targets and "
        f"{DEFAULT_LIMITS.max_ports_per_target} ports per target"
    ) in text
    assert f"more than {MAX_DNS_ANSWERS} answers is refused" in text
    assert f"more than {DEFAULT_LIMITS.max_targets} targets (target: '10.0.0.0/8')" in README
