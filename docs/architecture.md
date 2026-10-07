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

The check also runs inside pytest, with tests that plant violations in a temporary tree.

## Dependencies

| Package | Kind | Reason |
|---------|------|--------|
| cryptography | runtime (declared when first used, Phase 4) | See below. |
| PyYAML | runtime (declared when first used) | Rules and the port preset are YAML data (decision D3). The stdlib has no YAML parser. Loaded with `yaml.safe_load` only. |
| hatchling | build | Build backend for the src layout. Not installed at runtime. |
| pytest, pytest-cov | dev | Test runner and the coverage threshold in the gate. |
| ruff | dev | Lint and format. |
| mypy | dev | Strict type check on both platform settings. |

`pyproject.toml` declares no runtime dependency yet because nothing imports one.
Each is added in the phase that first uses it.

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
