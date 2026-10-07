# network-scanner

A defensive TCP connect scanner and attack-surface drift monitor for home labs and
networks you are authorized to test.

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

## Status

Under construction. Only the project scaffold exists so far; there is no scanning
functionality yet. The one working command is:

```
network-scanner --version
```

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
