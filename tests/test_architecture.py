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
