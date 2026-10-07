# Architecture notes

This file records design decisions and the reason for every dependency. It grows with
the project; the full architecture description is added in a later phase. The approved
plan is [PLAN.md](../PLAN.md).

## Layers

Packages under `src/network_scanner` sit in numbered layers (`core` 0; `scope`, `ports`
1; `net`, `rules` 2; `engine` 3; `fingerprint`, `findings` 4; `baseline`, `output` 5;
`lab` 6; `cli` 7). `scripts/check_architecture.py` enforces, with the AST:

1. A module may import only from its own layer number or a lower one. Packages that
   share a layer number may therefore import each other; the layer table in the script
   is the single source of truth.
2. Only `net`, `lab` and `cli` may import `socket`, `ssl`, `time` or `random`, use the
   `asyncio` stream APIs, or call `datetime.now()`, `utcnow()` or `today()`. Decision
   logic receives clocks, sleepers, resolvers and connectors through the interfaces in
   `core/interfaces.py`.
3. Dynamic imports (`__import__`, `importlib.import_module`) are rejected, since they
   would bypass the two rules above.
4. A package that is not in the layer table is itself a violation, so a new package
   cannot be added without deciding its layer.
5. There are no import cycles, neither between modules (`import_cycle`) nor between
   packages (`package_cycle`; this is how a cycle between peer packages on one layer
   is caught). Imports inside functions and under `if TYPE_CHECKING` count. A module also
   depends on its parent packages, because importing it runs their `__init__` first, so a
   package `__init__` must not import its own submodules.

The check also runs inside pytest, with tests that plant violations in a temporary tree.

## Dependencies

| Package | Kind | Reason |
|---------|------|--------|
| cryptography | runtime (declared when first used, Phase 4) | See below. |
| PyYAML | runtime (declared in Phase 2; first imported by `ports/presets.py`) | The `common` port preset is YAML data and so will be the rules (decision D3). The stdlib has no YAML parser. Loaded with `yaml.safe_load` only; before loading, an event-stream check refuses anchors, aliases, explicit tags, duplicate keys and deep nesting (see `docs/ports.md`). `tests/test_ports_presets.py` fails if any source file calls an unsafe loader. |
| hatchling | build | Build backend for the src layout. Not installed at runtime. |
| pytest, pytest-cov | dev | Test runner and the coverage threshold in the gate. |
| ruff | dev | Lint and format. |
| mypy | dev | Strict type check on both platform settings. |
| types-PyYAML | dev | Type stubs, so mypy can stay strict. |

`pyproject.toml` declares a runtime dependency only in the phase whose code first imports
it: PyYAML since Phase 2, `cryptography` from Phase 4.

PyYAML wheels, checked 2026-10-07 the same way as below (`uv pip compile --only-binary
:all:`): PyYAML 6.0.3 and types-PyYAML resolve for Python 3.11, 3.12 and 3.13 on
`x86_64-pc-windows-msvc` and `x86_64-manylinux_2_39`.

### Why `cryptography` (decision D1)

With verification switched off, Python's `ssl` module returns the peer certificate only
as raw DER bytes, and the standard library has no public X.509 parser. The options were
a hand-written DER parser or a maintained library. A hand-written parser would be the
largest piece of untrusted-input parsing in the project. Certificates come from servers
we do not control, so we use `cryptography` (parsing in a widely reviewed library)
instead of writing our own.

It also lets us report two separate facts about a certificate (decision D6):
"self-issued" (issuer equals subject) and "signature verifies against its own key",
the latter using the library's signature verification.

### Wheel availability, checked 2026-10-07

Checked against PyPI for `cryptography` 50.0.2 (the latest release at that time):

- The release has `cp311-abi3` wheels for `win_amd64` and for `manylinux_2_28_x86_64`
  (and other manylinux and musllinux variants). A `cp311-abi3` wheel installs on
  CPython 3.11, 3.12 and 3.13.
- `uv pip compile --only-binary :all:` resolves `cryptography` for each of Python 3.11,
  3.12 and 3.13 on `x86_64-pc-windows-msvc` and `x86_64-manylinux_2_39` without needing
  a source build.

This shows that wheels exist for the platforms CI uses. It is not a test of importing
the package on every combination; CI does that once the dependency is declared.

## Other decisions

- D2: no committed key or certificate. The demo and the tests generate an ephemeral
  self-signed certificate at runtime into a temporary directory that is deleted
  afterwards.
- D4: `169.254.0.0/16` (including cloud metadata `169.254.169.254`) is always refused;
  `100.64.0.0/10` (CGNAT) is treated as public.
- D5: the port preset is a curated `common` list of well-known service ports,
  documented as curated, not frequency-ranked.
- No ATT&CK mapping in v1. An open port is not an observed technique. Findings carry
  evidence text and, only where precise, a CWE or RFC reference.

## Scope and ports (Phase 2)

Details are in [scope-policy.md](scope-policy.md) and [ports.md](ports.md). Design points
that are not obvious from the code:

- Address parsing and formatting are our own (`scope/parser.py`). `ipaddress` and
  `socket` are used only inside tests, as a cross-check: an exhaustive test over small
  alphabets compares our IPv4 acceptance with `inet_aton` and our IPv6 acceptance and
  formatting with `ipaddress`.
- Classification is a table of CIDR blocks with the most specific block winning, and a
  second lookup that reports which classes occur in an address range without iterating
  it. Both are in `scope/classify.py`; the table in the documentation is generated from it.
- `plan_targets` (in `scope/policy.py`) is the single entry point that turns target
  strings into the pinned scan list. It takes the resolver and the confirmation callback
  as arguments, so it needs no network and no terminal in tests.
- Reason codes live in `core/errors.py` with the other shared error types. Phase 2 added
  fifteen to the six the plan names.
- Fixed input bounds that are not per-run settings (answers per name, resolve timeout,
  scope-file size, port-spec length) are constants in `core/limits.py`, not fields of
  `Limits`, so the report schema is unchanged.
- Interpretations that go beyond the plan, all on the conservative side: IPv6 space that
  is not global unicast, unique-local, link-local, loopback or a listed special block is
  refused as `reserved`; `192.0.0.0/24`, `192.88.99.0/24` and `64:ff9b:1::/48` are refused;
  a name with more than eight answers is refused rather than truncated.
