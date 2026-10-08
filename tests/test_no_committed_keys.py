"""Decision D2: no key or certificate is ever committed.

TLS test material is generated at runtime into a temporary directory. This test fails if a
private key or a certificate is tracked by git, by file name and by content. The patterns
below are written so that this file does not match them itself.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_SCANNED_BYTES = 2 * 1024 * 1024

KEY_SUFFIXES = frozenset(
    {".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore", ".p8", ".pk8"}
)
# "-----BEGIN <label>-----" for a private key of any kind or for a certificate.
PEM_BLOCK = re.compile(rb"-{5}BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-{5}")
# A PuTTY private key file starts with this header line.
PUTTY_KEY = re.compile(rb"^PuTTY-User-Key-File-[0-9]+:", re.MULTILINE)


def find_key_material(files: Iterable[tuple[str, bytes]]) -> list[str]:
    """Describe every (posix path, content) pair that looks like a key or a certificate."""
    found = []
    for path, content in files:
        name = PurePosixPath(path)
        if name.suffix.lower() in KEY_SUFFIXES:
            found.append(f"{path}: key or certificate file name")
        elif PEM_BLOCK.search(content) or PUTTY_KEY.search(content):
            found.append(f"{path}: key or certificate content")
    return found


def tracked_files(root: Path, git: str) -> list[tuple[str, bytes]]:
    listing = subprocess.run(  # noqa: S603
        [git, "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert listing.returncode == 0, listing.stderr.decode("utf-8", "replace")
    files = []
    for raw in listing.stdout.split(b"\x00"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        try:
            with (root / path).open("rb") as handle:
                content = handle.read(MAX_SCANNED_BYTES)
        except OSError:
            content = b""  # deleted in the working tree; the name was still checked
        files.append((path, content))
    return files


def git_or_skip() -> str:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed, so the tracked files cannot be listed")
    return git


def pem(label: str) -> bytes:
    return b"-" * 5 + b"BEGIN " + label.encode("ascii") + b"-" * 5 + b"\nAAAA\n"


@pytest.mark.parametrize(
    "path",
    ["a.pem", "dir/server.KEY", "x/y.crt", "lab/cert.der", "id.p12", "k.pfx", "t.jks", "k.p8"],
)
def test_key_and_certificate_file_names_are_found(path: str) -> None:
    assert find_key_material([(path, b"")]) == [f"{path}: key or certificate file name"]


@pytest.mark.parametrize(
    "label",
    ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "CERTIFICATE"],
)
def test_pem_blocks_are_found_whatever_the_file_name(label: str) -> None:
    assert find_key_material([("notes.txt", b"text\n" + pem(label))]) == [
        "notes.txt: key or certificate content"
    ]


def test_putty_private_keys_are_found() -> None:
    content = b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"
    assert find_key_material([("k.ppk", content)]) == ["k.ppk: key or certificate content"]


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("README.md", b"We do not commit certificates.\n"),
        ("src/tls.py", b"PEM files are written at runtime.\n"),
        ("pub.txt", pem("PUBLIC KEY")),  # a public key alone is not secret
        ("keys.py", b"key_file = 'x'\n"),
    ],
)
def test_ordinary_files_are_not_flagged(path: str, content: bytes) -> None:
    assert find_key_material([(path, content)]) == []


def test_a_key_tracked_by_git_is_detected(tmp_path: Path) -> None:
    """The check works on a real repository, using the same listing as the repository test."""
    git = git_or_skip()
    subprocess.run([git, "init", "-q"], cwd=tmp_path, check=True, timeout=60)  # noqa: S603
    (tmp_path / "innocent.txt").write_bytes(b"hello\n")
    (tmp_path / "secret.txt").write_bytes(pem("EC PRIVATE KEY"))
    (tmp_path / "server.pem").write_bytes(b"x")
    subprocess.run(  # noqa: S603
        [git, "add", "--", "innocent.txt", "secret.txt", "server.pem"],
        cwd=tmp_path,
        check=True,
        timeout=60,
    )
    assert find_key_material(tracked_files(tmp_path, git)) == [
        "secret.txt: key or certificate content",
        "server.pem: key or certificate file name",
    ]


def test_no_private_key_or_certificate_is_tracked_by_git() -> None:
    git = git_or_skip()
    inside = subprocess.run(  # noqa: S603
        [git, "rev-parse", "--is-inside-work-tree"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if inside.returncode != 0:
        pytest.skip("this is not a git work tree (for example an unpacked source archive)")
    files = tracked_files(REPO_ROOT, git)
    assert files, "git reports no tracked files, so the check would prove nothing"
    assert find_key_material(files) == []


def test_gitignore_keeps_key_material_out_of_the_index() -> None:
    patterns = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert {"*.pem", "*.key", "*.crt", "*.der", "*.p12", "*.pfx"} <= set(patterns)
