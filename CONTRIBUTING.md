# Contributing

network-scanner is a small, deliberately bounded tool: a TCP connect scanner and attack-surface
drift monitor for networks you are authorized to test. The version 1.0 scope, and what is out of
scope (UDP, raw or stealth scanning, OS fingerprinting, CVE matching, credential testing, crawling,
distributed scanning, a GUI), is fixed in [PLAN.md](PLAN.md). A change that widens it is unlikely
to be accepted; a fix, a test, a clearer document or a new fingerprint or finding rule is welcome.

Scan only networks you own or have written permission to scan. Unauthorized scanning can be
illegal. Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Setup

```
uv venv --python 3.13 .venv
uv pip install -e ".[dev]"
python scripts/gate.py
```

The gate must pass before a commit. It runs ruff (lint and format check), mypy for both
`--platform linux` and `--platform win32`, the architecture check
([scripts/check_architecture.py](scripts/check_architecture.py)) and pytest with a coverage
threshold. CI runs it on Linux and Windows with Python 3.11, 3.12 and 3.13.

## Rules that the checks and reviews hold to

- **Safety design is not negotiable.** Default scope, the public-address gate, the always-refused
  ranges, resolve-once-and-pin, validate-everything-before-connecting and the hard caps are
  described in [docs/scope-policy.md](docs/scope-policy.md). No raw sockets, no stealth or
  evasion, no exploitation, no credential testing, no CVE matching.
- **Layers.** Imports point downward only, and only `net`, `lab` and `cli` touch sockets, clocks or
  randomness ([docs/architecture.md](docs/architecture.md)). Decision logic receives clocks,
  resolvers and connectors as arguments.
- **Everything from the network is hostile.** Banners, headers, certificates and DNS answers get
  size caps, deadlines and sanitising before they are stored, matched or shown. Nothing from the
  network is ever put into a shell command or HTML.
- **Tests are deterministic and stay on loopback.** No sleeping to synchronise, no real DNS, no
  host other than loopback; servers bind `127.0.0.1` on ephemeral ports. No key or certificate is
  committed (certificates are generated at runtime). Documentation may use only the documentation
  address ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.
- **Dependencies:** the default answer is no. Prefer the standard library; a new dependency needs a
  written reason in [docs/architecture.md](docs/architecture.md).
- **Truthfulness.** A claim in the README links to the test or document that proves it. Measured
  numbers (timings, counts, coverage) live only in [docs/performance.md](docs/performance.md).
  Generated tables get a drift test.
- **Cross-platform.** Pass `encoding="utf-8"` to `open()`; use `Path.as_posix()` for anything
  compared, stored or printed; keep Windows-only APIs behind `sys.platform` guards.

## Rule files

Fingerprint and finding rules are the YAML files under `src/network_scanner/rules/data/`. A new
rule needs a positive and a negative test, and the generated tables in
[docs/rules.md](docs/rules.md) must be updated (the drift test tells you what they should say).
`network-scanner rules validate` checks a file against the schema. References are CWE ids and RFC
numbers, only where they are precise; there is no ATT&CK mapping.

## Commits

Small [Conventional Commits](https://www.conventionalcommits.org/), one logical change each, made
with the gate green.
