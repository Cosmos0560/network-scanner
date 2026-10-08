"""Every relative link in the Markdown documents points at a file that exists, and every
anchor points at a heading that exists. A renamed test or document cannot leave a dead link."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCUMENTS = sorted(
    [*REPO_ROOT.glob("*.md"), *(REPO_ROOT / "docs").glob("*.md")],
    key=lambda path: path.as_posix(),
)
LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^(```|~~~)")


def strip_fences(text: str) -> str:
    """The text without fenced code blocks, where `](` and `#` are not links or headings."""
    kept: list[str] = []
    fenced = False
    for line in text.split("\n"):
        if FENCE.match(line.lstrip()):
            fenced = not fenced
            continue
        if not fenced:
            kept.append(line)
    return "\n".join(kept)


def strip_code(text: str) -> str:
    """As `strip_fences`, and without inline code too."""
    return re.sub(r"`[^`\n]*`", "", strip_fences(text))


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = heading.replace("`", "").strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: dict[str, int] = {}
    result: set[str] = set()
    for line in strip_fences(path.read_text(encoding="utf-8")).split("\n"):
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match is None:
            continue
        base = slug(match.group(1))
        count = found.get(base, 0)
        found[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def links_of(path: Path) -> list[str]:
    return LINK.findall(strip_code(path.read_text(encoding="utf-8")))


def test_the_documents_to_check_are_found() -> None:
    names = {path.relative_to(REPO_ROOT).as_posix() for path in DOCUMENTS}
    assert {"README.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md", "docs/cli.md"} <= names


@pytest.mark.parametrize(
    "document", DOCUMENTS, ids=lambda path: path.relative_to(REPO_ROOT).as_posix()
)
def test_every_relative_link_and_anchor_resolves(document: Path) -> None:
    problems: list[str] = []
    for target in links_of(document):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target):
            continue  # an absolute URL; nothing is fetched
        path_part, _, fragment = target.partition("#")
        destination = document if not path_part else (document.parent / path_part).resolve()
        if not destination.exists():
            problems.append(f"{target}: no such file")
            continue
        if fragment and destination.suffix == ".md" and fragment not in anchors(destination):
            problems.append(f"{target}: no such heading")
    assert problems == []


def test_the_slug_rule_matches_the_headings_the_documents_link_to() -> None:
    assert slug("Certificates (decisions D1, D2 and D6)") == "certificates-decisions-d1-d2-and-d6"
    assert slug("Scanning (Phase 3)") == "scanning-phase-3"
    assert slug("Scope: what is scanned") == "scope-what-is-scanned"
    assert slug("What the `scanner` sends") == "what-the-scanner-sends"


def test_a_dead_link_would_be_found(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("[gone](missing.md) [here](#top)\n\n# Top\n\n```\n[code](nope.md)\n```\n")
    assert links_of(page) == ["missing.md", "#top"]
    assert anchors(page) == {"top"}
    assert not (tmp_path / "missing.md").exists()
