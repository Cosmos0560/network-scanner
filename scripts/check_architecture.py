"""Architecture check (PLAN.md section 1). Standard library only, AST based.

Enforces, for every module under src/network_scanner:

1. layer order: a module may import only from its own layer or a lower one;
2. I/O quarantine: only `net`, `lab` and `cli` may import socket, ssl, time or random,
   use asyncio stream APIs, or call datetime.now()-style clock functions;
3. no dynamic imports (`__import__`, `importlib.import_module`), which would bypass 1 and 2;
4. every package under network_scanner must be listed in LAYERS below;
5. no import cycles, at module level (`import_cycle`) and between packages
   (`package_cycle`, which is how cycles between peer packages on one layer show up).
   Imports inside functions and under `if TYPE_CHECKING` count. A module also depends on
   its parent packages, because importing it runs their `__init__` first; a package
   `__init__` that imports its own submodules is therefore a cycle.

Run `python scripts/check_architecture.py`; exit status is 1 when violations are found.
All paths are printed with as_posix().
"""

from __future__ import annotations

import ast
import sys
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT_PACKAGE = "network_scanner"

LAYERS: dict[str, int] = {
    "core": 0,
    "scope": 1,
    "ports": 1,
    "net": 2,
    "rules": 2,
    "engine": 3,
    "fingerprint": 4,
    "findings": 4,
    "baseline": 5,
    "output": 5,
    "lab": 6,
    "cli": 7,
}

IO_PACKAGES = frozenset({"net", "lab", "cli"})
BANNED_MODULES = frozenset({"socket", "ssl", "time", "random"})
ASYNCIO_STREAM_NAMES = frozenset(
    {
        "open_connection",
        "start_server",
        "open_unix_connection",
        "start_unix_server",
        "StreamReader",
        "StreamWriter",
        "StreamReaderProtocol",
        "streams",
    }
)
CLOCK_CALLS = frozenset({"now", "utcnow", "today"})
DYNAMIC_IMPORTS = frozenset({"__import__", "import_module"})


@dataclass(frozen=True, slots=True)
class Violation:
    path: str  # as_posix(), relative to the scanned src directory
    line: int
    code: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.code}: {self.message}"


@dataclass(frozen=True, slots=True)
class RawImport:
    """One import statement, resolved to absolute dotted parts."""

    line: int
    module: tuple[str, ...]
    names: tuple[str, ...]


def _module_parts(src_dir: Path, file: Path) -> tuple[str, ...]:
    return file.relative_to(src_dir).with_suffix("").parts


def _resolve_from(
    node: ast.ImportFrom, package: tuple[str, ...]
) -> tuple[tuple[str, ...] | None, tuple[str, ...]]:
    """Return (absolute module parts or None if it escapes the tree, imported names)."""
    names = tuple(alias.name for alias in node.names)
    if node.level == 0:
        return tuple((node.module or "").split(".")), names
    if node.level - 1 > len(package) - 1:
        return None, names
    base = package[: len(package) - (node.level - 1)]
    extra = tuple(node.module.split(".")) if node.module else ()
    return base + extra, names


class _FileChecker(ast.NodeVisitor):
    def __init__(self, rel: str, package: tuple[str, ...], layer_pkg: str | None) -> None:
        self.rel = rel
        self.package = package
        self.layer_pkg = layer_pkg
        self.violations: list[Violation] = []
        self.imports: list[RawImport] = []
        self.asyncio_aliases: set[str] = set()
        self.datetime_module_aliases: set[str] = set()
        self.datetime_class_aliases: set[str] = set()

    # -- helpers ---------------------------------------------------------------------
    def _add(self, node: ast.AST, code: str, message: str) -> None:
        self.violations.append(Violation(self.rel, getattr(node, "lineno", 0), code, message))

    @property
    def _io_allowed(self) -> bool:
        return self.layer_pkg in IO_PACKAGES

    def _check_target_layer(self, node: ast.AST, target: str) -> None:
        if target not in LAYERS:
            self._add(node, "unknown_layer", f"import of unmapped package {ROOT_PACKAGE}.{target}")
            return
        if self.layer_pkg is None:
            self._add(node, "layer_order", f"{ROOT_PACKAGE}/__init__ must not import {target}")
        elif LAYERS[target] > LAYERS[self.layer_pkg]:
            self._add(
                node,
                "layer_order",
                f"{self.layer_pkg} (layer {LAYERS[self.layer_pkg]}) imports "
                f"{target} (layer {LAYERS[target]})",
            )

    def _check_internal(self, node: ast.AST, module: tuple[str, ...], names: Iterable[str]) -> None:
        if not module or module[0] != ROOT_PACKAGE:
            return
        if len(module) >= 2:
            self._check_target_layer(node, module[1])
            return
        for name in names:  # `from network_scanner import X`
            if name in LAYERS:
                self._check_target_layer(node, name)
            elif name == "*":
                self._add(node, "unknown_layer", "star import from the root package")

    def _check_banned(self, node: ast.AST, module: tuple[str, ...]) -> None:
        if self._io_allowed or not module:
            return
        if module[0] in BANNED_MODULES:
            self._add(node, "io_quarantine", f"import of {module[0]} outside net/lab/cli")
        elif module[:2] == ("asyncio", "streams"):
            self._add(node, "io_quarantine", "import of asyncio.streams outside net/lab/cli")

    # -- visitors --------------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module = tuple(alias.name.split("."))
            self.imports.append(RawImport(node.lineno, module, ()))
            self._check_internal(node, module, ())
            self._check_banned(node, module)
            bound = alias.asname or module[0]
            if module[0] == "asyncio":
                self.asyncio_aliases.add(bound)
            if module[0] == "datetime":
                self.datetime_module_aliases.add(bound)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module, names = _resolve_from(node, self.package)
        if module is None:
            self._add(node, "layer_order", "relative import escapes the package tree")
            return
        self.imports.append(RawImport(node.lineno, module, names))
        self._check_internal(node, module, names)
        self._check_banned(node, module)
        if module == ("asyncio",) and not self._io_allowed:
            for name in names:
                if name in ASYNCIO_STREAM_NAMES:
                    self._add(node, "io_quarantine", f"asyncio.{name} outside net/lab/cli")
        if module == ("datetime",):
            for alias in node.names:
                if alias.name in {"datetime", "date"}:
                    self.datetime_class_aliases.add(alias.asname or alias.name)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        value = node.value
        if not self._io_allowed:
            if (
                isinstance(value, ast.Name)
                and value.id in self.asyncio_aliases
                and node.attr in ASYNCIO_STREAM_NAMES
            ):
                self._add(node, "io_quarantine", f"asyncio.{node.attr} outside net/lab/cli")
            if node.attr in CLOCK_CALLS and self._is_datetime_class(value):
                self._add(node, "io_quarantine", f"datetime.{node.attr}() outside net/lab/cli")
        self.generic_visit(node)

    def _is_datetime_class(self, value: ast.expr) -> bool:
        if isinstance(value, ast.Name):
            return value.id in self.datetime_class_aliases
        return (
            isinstance(value, ast.Attribute)
            and value.attr in {"datetime", "date"}
            and isinstance(value.value, ast.Name)
            and value.value.id in self.datetime_module_aliases
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name in DYNAMIC_IMPORTS:
            self._add(node, "dynamic_import", f"{name}() is not allowed")
        self.generic_visit(node)


def _analyse_file(src_dir: Path, file: Path) -> tuple[list[Violation], list[RawImport]]:
    rel = file.relative_to(src_dir).as_posix()
    parts = _module_parts(src_dir, file)
    if parts[0] != ROOT_PACKAGE:
        return [], []
    try:
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=rel)
    except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
        return [Violation(rel, getattr(exc, "lineno", 0) or 0, "unparseable", str(exc))], []

    layer_pkg: str | None
    if len(parts) == 2 and parts[1] == "__init__":
        layer_pkg = None
    elif len(parts) >= 3 and parts[1] in LAYERS:
        layer_pkg = parts[1]
    else:
        message = "module is not in a package listed in LAYERS"
        return [Violation(rel, 1, "unknown_layer", message)], []

    checker = _FileChecker(rel, parts[:-1], layer_pkg)
    checker.visit(tree)
    return checker.violations, checker.imports


def check_file(src_dir: Path, file: Path) -> list[Violation]:
    """Per-file rules (layer order, I/O quarantine, dynamic imports). Cycles need the tree."""
    return _analyse_file(src_dir, file)[0]


Edges = dict[tuple[str, str], tuple[str, int]]  # (source, target) -> (path, line) of an import


def _module_name(parts: tuple[str, ...]) -> str:
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _package_of(module: str) -> str | None:
    """The layer package a module belongs to, or None for the root and unmapped modules."""
    parts = module.split(".")
    return parts[1] if len(parts) >= 2 and parts[1] in LAYERS else None


def _import_targets(item: RawImport, known: set[str]) -> set[str]:
    """Modules of the tree that an import statement loads directly."""
    sizes = range(len(item.module), 0, -1)
    prefixes = [".".join(item.module[:size]) for size in sizes]
    base = next((prefix for prefix in prefixes if prefix in known), None)
    if item.module[:1] != (ROOT_PACKAGE,) or base is None:
        return set()
    targets = {base}
    for name in item.names:  # `from package import submodule`
        candidate = ".".join((*item.module, name))
        if candidate in known:
            targets.add(candidate)
    return targets


def _parents(module: str, known: set[str]) -> list[str]:
    parts = module.split(".")
    prefixes = (".".join(parts[:size]) for size in range(1, len(parts)))
    return [prefix for prefix in prefixes if prefix in known]


def _strongly_connected(adjacency: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan's algorithm, iterative. Components are returned sorted, in a stable order."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    for root in sorted(adjacency):
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(adjacency[root]))]
        while work:
            node, neighbours = work[-1]
            descended = False
            for neighbour in neighbours:
                if neighbour not in index:
                    index[neighbour] = low[neighbour] = counter
                    counter += 1
                    stack.append(neighbour)
                    on_stack.add(neighbour)
                    work.append((neighbour, iter(adjacency[neighbour])))
                    descended = True
                    break
                if neighbour in on_stack:
                    low[node] = min(low[node], index[neighbour])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(sorted(component))
    return sorted(components)


def _shortest_cycle(adjacency: dict[str, list[str]], component: list[str]) -> list[str]:
    """A shortest cycle through the smallest member, as [start, ..., start]."""
    members = set(component)
    start = component[0]
    previous: dict[str, str] = {}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbour in adjacency[node]:
            if neighbour not in members:
                continue
            if neighbour == start:
                path = [node]
                while path[-1] != start:
                    path.append(previous[path[-1]])
                return [*reversed(path), start]
            if neighbour not in previous:
                previous[neighbour] = node
                queue.append(neighbour)
    raise AssertionError("a strongly connected component of size > 1 contains a cycle")


def _cycle_violations(edges: Edges, code: str, noun: str) -> list[Violation]:
    """One violation per strongly connected component of the graph given by `edges`."""
    adjacency: dict[str, list[str]] = {}
    for source, target in sorted(edges):
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    violations: list[Violation] = []
    for component in _strongly_connected(adjacency):
        if len(component) < 2:
            continue
        cycle = _shortest_cycle(adjacency, component)
        path, line = edges[(cycle[0], cycle[1])]
        message = f"{noun} import cycle: {' -> '.join(cycle)}"
        violations.append(Violation(path, line, code, message))
    return violations


def _add_edge(edges: Edges, key: tuple[str, str], at: tuple[str, int]) -> None:
    if key not in edges or at < edges[key]:
        edges[key] = at


def _cycle_check(modules: dict[str, str], imports: dict[str, list[RawImport]]) -> list[Violation]:
    """Import cycles between modules and between layer packages.

    `modules` maps a dotted module name to its posix path; `imports` maps a module name to
    the imports found in it.
    """
    known = set(modules)
    module_edges: Edges = {}
    package_edges: Edges = {}
    for module in sorted(known):
        for parent in _parents(module, known):  # importing a module runs its parents first
            _add_edge(module_edges, (module, parent), (modules[module], 1))
        for item in imports.get(module, []):
            for target in _import_targets(item, known):
                if target == module:
                    continue
                at = (modules[module], item.line)
                _add_edge(module_edges, (module, target), at)
                source_pkg, target_pkg = _package_of(module), _package_of(target)
                if source_pkg and target_pkg and source_pkg != target_pkg:
                    _add_edge(package_edges, (source_pkg, target_pkg), at)
    return _cycle_violations(module_edges, "import_cycle", "module") + _cycle_violations(
        package_edges, "package_cycle", "package"
    )


def check_tree(src_dir: Path) -> list[Violation]:
    """Check every .py file under `src_dir`/network_scanner, in a stable order."""
    package_dir = src_dir / ROOT_PACKAGE
    files = sorted(package_dir.rglob("*.py"), key=lambda p: p.relative_to(src_dir).as_posix())
    violations: list[Violation] = []
    modules: dict[str, str] = {}
    imports: dict[str, list[RawImport]] = {}
    for file in files:
        found, raw_imports = _analyse_file(src_dir, file)
        violations.extend(found)
        name = _module_name(_module_parts(src_dir, file))
        modules[name] = file.relative_to(src_dir).as_posix()
        imports[name] = raw_imports
    cycles = _cycle_check(modules, imports)
    return violations + sorted(cycles, key=lambda v: (v.path, v.line, v.code, v.message))


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    src_dir = Path(args[0]) if args else Path(__file__).resolve().parent.parent / "src"
    violations = check_tree(src_dir)
    for violation in violations:
        print(violation.render())
    if violations:
        print(f"architecture check failed: {len(violations)} violation(s)")
        return 1
    print("architecture check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
