# Security review of release 1.0.0

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

What was checked before 1.0.0, with what, what came out, and what was accepted and why. The design
side is in [threat-model.md](threat-model.md); the tests that back each safety claim are listed in
the claim table of the [README](../README.md#claims-and-evidence).

This page reports what was run. It is not an audit by a third party, and no claim is made beyond
what is written here.

## Release checks

Run on 2026-10-08 on Windows 11 with Python 3.13, against a fresh clone of the commit under test,
in temporary virtual environments created outside the repository and deleted afterwards. Nothing
the checks built was committed (`build/` and `dist/` are ignored by git). The only host contacted
was PyPI (build backend, installs and the `pip-audit` vulnerability service); the demo used
loopback only. The commit under test was `e360e31`. The commits after it change documentation
and tests, and in `src/` only a comment in `rules/data/findings.yaml` and two docstrings in
`rules/findings_schema.py` that name the document holding the generated rule tables; no
executable line under `src/` differs.

| Check | How | Result |
|-------|-----|--------|
| Build | `python -m build` (build backend hatchling 1.32.4) | Built `network_scanner-1.0.0.tar.gz` and `network_scanner-1.0.0-py3-none-any.whl`. The wheel holds the package, `py.typed`, the three YAML data files (`ports_common.yaml`, `fingerprints.yaml`, `findings.yaml`) and the licence. |
| Install | The wheel installed into a clean virtual environment (not the development one); the three commands run from a different directory | `network-scanner --version` printed `network-scanner 1.0.0`; `network-scanner rules validate` printed `OK: built-in fingerprint rules (9 rules)` (and `--kind findings` the finding rules) with exit code 0; `network-scanner demo` exited 0 and named the four lab services. The package was imported from the environment's `site-packages`, not from the checkout. |
| Dependencies | `pip-audit` 2.10.1 on the pinned runtime dependencies of that environment, `--no-deps --disable-pip` | `No known vulnerabilities found` (exit 0). Audited: `cryptography==50.0.2`, `cffi==2.1.1`, `pycparser==3.0`, `pyyaml==6.0.3`. |
| Static analysis | `bandit` 1.9.4, `-r src` | One finding, low severity and high confidence, accepted (below). Nothing of medium or high severity. |
| Gate | `python scripts/gate.py`: ruff (which includes the flake8-bandit `S` rules), ruff format, mypy for `linux` and `win32`, the architecture check, pytest with a coverage threshold | Passed before every commit. The figures are reported with the release, not here. |

The `pip-audit` run printed a warning that dependencies pinned with `--no-deps` should be hash
pinned; the list above was pinned by version only.

### Accepted: B101 `assert` in `findings/evaluate.py`

`bandit` reports B101 (use of `assert`) at the `assert found.service is not None` in
`src/network_scanner/findings/evaluate.py`, in the branch for a rule whose confidence is
`from_service`.

- **Why it is not a defect.** The assert states an invariant that is established elsewhere: the
  rule loader refuses a `from_service` confidence on a rule without a `service` condition (the
  schema error is `invalid_value` at `rules[N].confidence`, tested in `tests/test_findings.py`),
  and `rule_applies` returns false before this code runs unless the port has that service. No
  input reaches the assert with a missing service.
- **What the assert is for.** It narrows the type for mypy and documents the invariant. It is not
  a security check and nothing depends on it for safety.
- **If Python is run with `-O`**, the assert is removed. In the impossible state it guards, the
  next line would raise `AttributeError` instead of `AssertionError`; both end the run through the
  same top-level handler, which prints an internal error and exits with code 3.

It is left as it is. The ruff rule for the same pattern (S101) is already silenced on that line
with a comment giving the reason.

## What was reviewed and what was not

Reviewed by running the tools above: the code under `src/`, and the runtime dependencies at the
versions that resolved on the day of the check.

Not covered by these checks:

- **`tests/` and `scripts/`** were not scanned by `bandit` (they do not ship in the wheel). Ruff's
  `S` rules cover them in the gate.
- **The development dependencies** (pytest, ruff, mypy and others) were not audited; they are not
  installed with the package.
- **The full range of allowed dependency versions.** `pyproject.toml` allows
  `cryptography>=42,<51`; only the version resolved on the day (and, in CI, the newest) is tested
  and audited. The lower bound is a statement about the API used (see
  [architecture.md](architecture.md#how-cryptography-is-used-and-its-version-range)).
- **`pip-audit` finds known vulnerabilities** in an advisory database. It does not find unknown
  ones, and says nothing about the dependencies' own dependencies beyond the four listed.
- **The sdist** is a source archive of the repository's non-ignored files, so it includes `tests/`,
  `docs/`, `PLAN.md` and `CLAUDE.md`. It was built and listed, not installed separately.
- **No signing, provenance or SBOM** is produced for the artifacts, and the package is not
  published to PyPI.

## Continuous integration review

`.github/workflows/ci.yml` was read for problems that can be identified from the file alone.

- Good: the workflow's `permissions` are `contents: read`; there are no secrets, no
  `pull_request_target`, and no steps that run code from a pull request with write access;
  concurrent runs of the same ref are cancelled; each job has a timeout; the runner image for
  Linux is pinned to `ubuntu-24.04`.
- Floating: `runs-on: windows-latest` follows whatever GitHub currently calls latest, so the
  Windows job can change under the project.
- Actions are pinned to major-version tags (`actions/checkout@v4`, `actions/setup-python@v5`),
  not to commit hashes; a tag can be moved by its owner.
- **Deprecated action versions: none can be identified from the file alone.** Whether `v4` and `v5`
  are still the current majors, or run on a runtime that GitHub has deprecated, cannot be told
  from this repository, and this review had no access to GitHub. Versions were deliberately not
  changed on a guess. This is a known gap: check the annotations on a recent Actions run, and
  GitHub's pages for those two actions, before relying on these versions.
- CI results are reported by the maintainer; nothing in this repository claims a CI state.

## Not verified

Collected here so that the list is in one place; the README's Limitations section has the same
items in more detail.

- Behaviour on real networks: dropped packets (`filtered`), a real DNS server, real SSH, HTTP and
  TLS servers. Every end-to-end test runs on loopback.
- A real Ctrl+C in a console on Windows and on Linux.
- Linux timing, and anything about Python 3.11 and 3.12 beyond what CI shows.
- The behaviour of the symbolic-link tests on the development machine: they are skipped on an
  account that cannot create symbolic links, and run on Linux in CI.
- The GitHub repository settings: that private vulnerability reporting is enabled, which
  [SECURITY.md](../SECURITY.md) relies on.
- The links to the GitHub repository in the README (the clone address and the CI badge): they
  assume the repository is `Cosmos0560/network-scanner`.
