# network-scanner

A defensive TCP connect scanner and attack-surface drift monitor for home labs and
networks you are authorized to test.

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

## Status

Under construction. The TCP connect scan works, checked end to end against loopback
listeners by [tests/test_e2e.py](tests/test_e2e.py); there is no service fingerprinting,
baseline or drift detection yet.

```
network-scanner --version
network-scanner scan 127.0.0.1 --ports 22,80,443
```

The scope rules (what is scanned by default and what needs explicit permission) are in
[docs/scope-policy.md](docs/scope-policy.md), how a scan is built and what it guarantees is
in [docs/architecture.md](docs/architecture.md), and timing observations are in
[docs/performance.md](docs/performance.md).

The approved plan is in [PLAN.md](PLAN.md) and the working rules are in
[CLAUDE.md](CLAUDE.md).

## Development

```
uv venv --python 3.13 .venv
uv pip install -e ".[dev]"
python scripts/gate.py
```

The gate runs ruff, mypy (Linux and Windows platform settings), the architecture check
and pytest with a coverage threshold. Design decisions and dependency reasons are in
[docs/architecture.md](docs/architecture.md).

## License

MIT, see [LICENSE](LICENSE).
