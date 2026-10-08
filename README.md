# network-scanner

A defensive TCP connect scanner and attack-surface drift monitor for home labs and
networks you are authorized to test.

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

## Status

Under construction; the README is rewritten in the last phase. What works today, each checked
end to end against loopback services by the tests named in
[docs/architecture.md](docs/architecture.md):

- a TCP connect scan that inspects each open port (a passive banner read, one HTTP `HEAD`
  request, a TLS handshake that reads the certificate without validating it), names the
  service, and reports findings with evidence, in table, JSON, JSON Lines and CSV form;
- a baseline of open ports and services, and a drift report against it (`baseline save` and
  `baseline diff`);
- a demo that scans a lab it starts itself on loopback (it needs no network);
- `network-scanner rules validate` for fingerprint and finding rule files.

```
network-scanner --version
network-scanner demo
network-scanner scan 127.0.0.1 --ports 22,80,443 --format json
network-scanner scan 127.0.0.1 --connect-only          # send nothing after connecting
network-scanner baseline save 127.0.0.1 --baseline lab.json
network-scanner baseline diff 127.0.0.1 --baseline lab.json
network-scanner rules validate --kind findings
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
