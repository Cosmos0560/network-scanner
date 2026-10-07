"""The architecture check must pass on the real tree and fail on planted violations."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import check_architecture as arch

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


def make_tree(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write `files` (paths relative to network_scanner/) into a throwaway src tree."""
    src = tmp_path / "src"
    package = src / "network_scanner"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    for rel, source in files.items():
        target = package / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return src


def codes(src: Path) -> list[str]:
    return [v.code for v in arch.check_tree(src)]


def test_the_real_tree_has_no_violations() -> None:
    assert arch.check_tree(SRC) == []


def test_the_script_passes_on_the_real_tree_in_a_real_process() -> None:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(REPO_ROOT / "scripts" / "check_architecture.py")],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout
    assert "passed" in completed.stdout


def test_every_package_on_disk_is_mapped_to_a_layer() -> None:
    on_disk = {
        p.name
        for p in (SRC / "network_scanner").iterdir()
        if p.is_dir() and p.name != "__pycache__"
    }
    assert on_disk <= set(arch.LAYERS)


# -- layer order -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "source"),
    [
        ("core/bad.py", "from network_scanner.scope import x\n"),
        ("core/bad.py", "import network_scanner.cli.main\n"),
        ("core/bad.py", "from network_scanner import cli\n"),
        ("core/bad.py", "from ..cli import main\n"),
        ("core/bad.py", "from .. import cli\n"),
        ("scope/bad.py", "from network_scanner.engine.scan import run\n"),
        ("engine/bad.py", "from network_scanner.cli import main\n"),
        ("net/bad.py", "from network_scanner.lab import servers\n"),
        ("output/bad.py", "from network_scanner.lab.servers import X\n"),
    ],
)
def test_importing_a_higher_layer_is_a_violation(tmp_path: Path, file: str, source: str) -> None:
    assert codes(make_tree(tmp_path, {file: source})) == ["layer_order"]


def test_the_root_package_may_not_import_layers(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {})
    (src / "network_scanner" / "__init__.py").write_text(
        "from network_scanner.core import errors\n", encoding="utf-8"
    )
    assert codes(src) == ["layer_order"]


def test_a_relative_import_that_escapes_the_tree_is_a_violation(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/bad.py": "from ... import x\n"})
    assert codes(src) == ["layer_order"]


@pytest.mark.parametrize(
    ("file", "source"),
    [
        ("core/ok.py", "from network_scanner.core import errors\n"),
        ("core/ok.py", "from . import errors\n"),
        ("core/ok.py", "from .errors import X\n"),
        ("scope/ok.py", "from network_scanner.core.model import X\n"),
        ("scope/ok.py", "from network_scanner.ports import spec\n"),  # same layer number
        ("engine/ok.py", "from ..net import connector\nfrom ..core import model\n"),
        ("cli/ok.py", "from network_scanner import __version__\n"),
        ("cli/ok.py", "from network_scanner import engine, lab, output\n"),
        ("lab/ok.py", "from network_scanner.net import tls\n"),
    ],
)
def test_importing_the_same_or_a_lower_layer_is_allowed(
    tmp_path: Path, file: str, source: str
) -> None:
    assert codes(make_tree(tmp_path, {file: source})) == []


# -- I/O quarantine ----------------------------------------------------------------------

BANNED_IO_SOURCES = [
    "import socket\n",
    "import socket as s\n",
    "from socket import socket\n",
    "import ssl\n",
    "from ssl import create_default_context\n",
    "import time\n",
    "from time import sleep\n",
    "import random\n",
    "from random import choice\n",
    "import asyncio.streams\n",
    "from asyncio import streams\n",
    "from asyncio import open_connection\n",
    "from asyncio import StreamReader as R\n",
    "import asyncio\nasyncio.open_connection('x', 1)\n",
    "import asyncio as aio\naio.start_server(None, 'x', 1)\n",
    "from datetime import datetime\ndatetime.now()\n",
    "from datetime import datetime as dt\ndt.utcnow()\n",
    "from datetime import date\ndate.today()\n",
    "import datetime\ndatetime.datetime.now()\n",
    "import datetime as d\nd.date.today()\n",
]


@pytest.mark.parametrize("source", BANNED_IO_SOURCES)
@pytest.mark.parametrize("layer", ["core", "scope", "ports", "rules", "engine", "baseline"])
def test_io_is_forbidden_outside_the_quarantine(tmp_path: Path, layer: str, source: str) -> None:
    assert codes(make_tree(tmp_path, {f"{layer}/bad.py": source})) == ["io_quarantine"]


@pytest.mark.parametrize("source", BANNED_IO_SOURCES)
@pytest.mark.parametrize("layer", ["net", "lab", "cli"])
def test_io_is_allowed_inside_the_quarantine(tmp_path: Path, layer: str, source: str) -> None:
    assert codes(make_tree(tmp_path, {f"{layer}/ok.py": source})) == []


def test_a_planted_socket_import_in_a_pure_layer_is_reported_with_its_location(
    tmp_path: Path,
) -> None:
    src = make_tree(tmp_path, {"core/pure.py": "x = 1\nimport socket\n"})
    [violation] = arch.check_tree(src)
    assert violation.code == "io_quarantine"
    assert violation.path == "network_scanner/core/pure.py"
    assert violation.line == 2
    assert "socket" in violation.message


@pytest.mark.parametrize(
    "source",
    [
        "import asyncio\n\nasync def f():\n    await asyncio.sleep(0)\n    asyncio.Semaphore(1)\n",
        "from asyncio import Semaphore, gather, run, wait_for\n",
        "from datetime import datetime, timezone\nx = datetime(2020, 1, 1, tzinfo=timezone.utc)\n",
        "from datetime import datetime\ny = datetime.fromisoformat('2020-01-01')\n",
        "import datetime\nz = datetime.timedelta(seconds=1)\n",
        "class C:\n    def now(self): ...\nC().now()\n",
    ],
)
def test_harmless_code_in_the_engine_is_not_flagged(tmp_path: Path, source: str) -> None:
    assert codes(make_tree(tmp_path, {"engine/ok.py": source})) == []


# -- dynamic imports, unknown packages, unparseable files ------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "__import__('socket')\n",
        "import importlib\nimportlib.import_module('socket')\n",
        "from importlib import import_module\nimport_module(name)\n",
    ],
)
@pytest.mark.parametrize("layer", ["core", "net", "cli"])
def test_dynamic_imports_are_forbidden_everywhere(tmp_path: Path, layer: str, source: str) -> None:
    assert "dynamic_import" in codes(make_tree(tmp_path, {f"{layer}/bad.py": source}))


def test_an_unmapped_package_is_a_violation(tmp_path: Path) -> None:
    assert codes(make_tree(tmp_path, {"mystery/mod.py": "x = 1\n"})) == ["unknown_layer"]


def test_a_stray_root_module_is_a_violation(tmp_path: Path) -> None:
    assert codes(make_tree(tmp_path, {"stray.py": "x = 1\n"})) == ["unknown_layer"]


def test_importing_an_unmapped_package_is_a_violation(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/bad.py": "from network_scanner.mystery import x\n"})
    assert codes(src) == ["unknown_layer"]


def test_a_star_import_from_the_root_package_is_a_violation(tmp_path: Path) -> None:
    assert codes(make_tree(tmp_path, {"core/bad.py": "from network_scanner import *\n"})) == [
        "unknown_layer"
    ]


def test_an_unparseable_file_is_a_violation(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/broken.py": "def (:\n"})
    assert codes(src) == ["unparseable"]


def test_a_non_utf8_file_is_a_violation(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {})
    (src / "network_scanner" / "core").mkdir()
    (src / "network_scanner" / "core" / "binary.py").write_bytes(b"x = '\xff'\n")
    assert codes(src) == ["unparseable"]


def test_files_outside_the_root_package_are_ignored(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {})
    other = src / "network_scanner" / "core"
    other.mkdir()
    # check_file is also callable directly; a file that is not under network_scanner is skipped.
    elsewhere = src / "other" / "mod.py"
    elsewhere.parent.mkdir()
    elsewhere.write_text("import socket\n", encoding="utf-8")
    assert arch.check_file(src, elsewhere) == []


# -- reporting ---------------------------------------------------------------------------


def test_violations_are_reported_in_a_stable_order_with_posix_paths(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/b.py": "import socket\n",
            "core/a.py": "import ssl\n",
            "scope/c.py": "import time\n",
        },
    )
    paths = [v.path for v in arch.check_tree(src)]
    assert paths == [
        "network_scanner/core/a.py",
        "network_scanner/core/b.py",
        "network_scanner/scope/c.py",
    ]
    assert all("\\" not in p for p in paths)


def test_main_returns_one_and_prints_each_violation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = make_tree(tmp_path, {"core/bad.py": "import socket\n"})
    assert arch.main([str(src)]) == 1
    out = capsys.readouterr().out
    assert "network_scanner/core/bad.py:1: io_quarantine:" in out
    assert "1 violation(s)" in out


def test_main_returns_zero_on_a_clean_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert arch.main([str(make_tree(tmp_path, {"core/ok.py": "x = 1\n"}))]) == 0
    assert "passed" in capsys.readouterr().out


def test_main_defaults_to_the_real_tree(capsys: pytest.CaptureFixture[str]) -> None:
    assert arch.main([]) == 0
    assert "passed" in capsys.readouterr().out


# -- import cycles -----------------------------------------------------------------------


def cycle_violations(src: Path) -> list[arch.Violation]:
    return [v for v in arch.check_tree(src) if v.code in {"import_cycle", "package_cycle"}]


def test_a_two_module_cycle_in_one_package_is_reported(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/a.py": "from network_scanner.core import b\n",
            "core/b.py": "\n\nfrom network_scanner.core import a\n",
        },
    )
    [violation] = arch.check_tree(src)
    assert violation.code == "import_cycle"
    assert violation.path == "network_scanner/core/a.py"
    assert violation.line == 1
    assert violation.message == (
        "module import cycle: network_scanner.core.a -> network_scanner.core.b"
        " -> network_scanner.core.a"
    )


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("from . import b\n", "from . import a\n"),
        ("from .b import X\n", "from .a import Y\n"),
        ("import network_scanner.core.b\n", "import network_scanner.core.a\n"),
        ("from network_scanner.core.b import X\n", "from ..core.a import Y\n"),
        ("def f():\n    from . import b\n", "def g():\n    from . import a\n"),
        (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from . import b\n",
            "from . import a\n",
        ),
    ],
)
def test_cycles_are_found_however_the_import_is_written(tmp_path: Path, a: str, b: str) -> None:
    src = make_tree(tmp_path, {"core/a.py": a, "core/b.py": b})
    assert [v.code for v in arch.check_tree(src)] == ["import_cycle"]


def test_a_three_module_cycle_is_reported_once_with_a_shortest_cycle(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/a.py": "from . import b\n",
            "core/b.py": "from . import c\n",
            "core/c.py": "from . import a\nfrom . import b\n",  # c -> b is a shorter detour
        },
    )
    [violation] = arch.check_tree(src)
    assert violation.code == "import_cycle"
    assert violation.message.count("->") == 3


def test_two_separate_cycles_are_reported_separately(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/a.py": "from . import b\n",
            "core/b.py": "from . import a\n",
            "core/c.py": "from . import d\n",
            "core/d.py": "from . import c\n",
        },
    )
    assert [v.path for v in arch.check_tree(src)] == [
        "network_scanner/core/a.py",
        "network_scanner/core/c.py",
    ]


def test_a_cycle_between_peer_packages_on_one_layer_is_a_package_cycle(tmp_path: Path) -> None:
    # No module-level cycle here: scope.a -> ports.b and ports.c -> scope.d.
    src = make_tree(
        tmp_path,
        {
            "scope/a.py": "from network_scanner.ports import b\n",
            "scope/d.py": "x = 1\n",
            "ports/b.py": "x = 1\n",
            "ports/c.py": "from network_scanner.scope import d\n",
        },
    )
    [violation] = arch.check_tree(src)
    assert violation.code == "package_cycle"
    assert violation.path == "network_scanner/ports/c.py"
    assert violation.message == "package import cycle: ports -> scope -> ports"


def test_a_module_level_cycle_between_peer_packages_reports_both_kinds(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "scope/a.py": "from network_scanner.ports import b\n",
            "ports/b.py": "from network_scanner.scope import a\n",
        },
    )
    assert sorted(v.code for v in arch.check_tree(src)) == ["import_cycle", "package_cycle"]


def test_a_cycle_across_layers_is_reported_in_addition_to_the_layer_violation(
    tmp_path: Path,
) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/a.py": "from network_scanner.scope import b\n",
            "scope/b.py": "from network_scanner.core import a\n",
        },
    )
    assert sorted(v.code for v in arch.check_tree(src)) == [
        "import_cycle",
        "layer_order",
        "package_cycle",
    ]


def test_a_package_init_that_imports_its_own_submodule_is_a_cycle(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/__init__.py": "from .a import X\n", "core/a.py": "X = 1\n"})
    [violation] = arch.check_tree(src)
    assert violation.code == "import_cycle"
    assert violation.message == (
        "module import cycle: network_scanner.core -> network_scanner.core.a"
        " -> network_scanner.core"
    )


def test_a_cycle_of_three_peer_packages_is_reported_as_one_package_cycle(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "net/a.py": "from network_scanner.rules import b\n",
            "rules/b.py": "from network_scanner.scope import c\n",
            "scope/c.py": "from network_scanner.net import a\n",
        },
    )
    codes_found = {v.code for v in arch.check_tree(src)}
    assert "package_cycle" in codes_found


@pytest.mark.parametrize(
    "files",
    [
        # diamond
        {
            "core/a.py": "from . import b, c\n",
            "core/b.py": "from . import d\n",
            "core/c.py": "from . import d\n",
            "core/d.py": "x = 1\n",
        },
        # chain across layers, downward only
        {
            "engine/a.py": "from network_scanner.net import b\n",
            "net/b.py": "from network_scanner.core import c\n",
            "core/c.py": "x = 1\n",
        },
        # importing your own package by name, and a sibling that does not import back
        {
            "core/a.py": "from network_scanner.core import b\n",
            "core/b.py": "x = 1\n",
        },
        # peers that depend on one side only
        {
            "scope/a.py": "from network_scanner.ports import b\n",
            "ports/b.py": "from network_scanner.core import c\n",
            "core/c.py": "x = 1\n",
        },
        # a module that only mentions itself in a string or comment
        {"core/a.py": "# from . import a\nNAME = 'network_scanner.core.a'\n"},
    ],
)
def test_acyclic_graphs_are_not_flagged(tmp_path: Path, files: dict[str, str]) -> None:
    assert cycle_violations(make_tree(tmp_path, files)) == []


def test_a_very_long_import_chain_does_not_hit_the_recursion_limit() -> None:
    count = 20_000  # far past Python's default recursion limit
    ring = {(f"m{i}", f"m{(i + 1) % count}"): ("p.py", i) for i in range(count)}
    [violation] = arch._cycle_violations(ring, "import_cycle", "module")
    assert violation.message.count("->") == count
    chain = {(f"m{i}", f"m{i + 1}"): ("p.py", i) for i in range(count)}
    assert arch._cycle_violations(chain, "import_cycle", "module") == []


def test_a_cycle_check_on_a_wide_tree_finishes(tmp_path: Path) -> None:
    files = {f"core/m{i}.py": f"from . import m{i + 1}\n" for i in range(200)}
    files["core/m200.py"] = "from . import m0\n"
    [violation] = cycle_violations(make_tree(tmp_path, files))
    assert violation.message.count("->") == 201


def test_cycle_reports_are_deterministic(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {
            "core/a.py": "from . import b, c\n",
            "core/b.py": "from . import a\n",
            "core/c.py": "from . import a\n",
        },
    )
    first = arch.check_tree(src)
    assert first == arch.check_tree(src)
    assert [v.code for v in first] == ["import_cycle"]


def test_imports_of_unknown_or_outside_modules_create_no_edges(tmp_path: Path) -> None:
    src = make_tree(
        tmp_path,
        {"core/a.py": "import os\nimport network_scanner.core.missing\nimport network_scanner\n"},
    )
    assert cycle_violations(src) == []


def test_main_fails_on_a_planted_cycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = make_tree(tmp_path, {"core/a.py": "from . import b\n", "core/b.py": "from . import a\n"})
    assert arch.main([str(src)]) == 1
    assert "import_cycle" in capsys.readouterr().out
