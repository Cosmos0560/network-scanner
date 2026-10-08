# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-08

The first release. Everything below is new. The scope of this version, and what is left out of it,
is fixed in [PLAN.md](PLAN.md); the limitations are in the README.

### Added

- **Scope policy.** Targets are IP addresses, CIDR blocks, IPv4 ranges and host names, parsed by a
  closed grammar that refuses decimal, hex, octal and short IPv4 forms, IPv4-mapped and other
  embedded IPv6 forms, and CIDRs with host bits set. Default scope is loopback, RFC 1918, IPv6
  unique-local and IPv6 link-local. Multicast, broadcast, reserved, documentation, benchmark and
  IPv4 link-local ranges are always refused. A public address needs `--allow-public`, an entry in a
  scope file and a confirmation. Host names are resolved once, every answer is checked, and one bad
  answer refuses the whole name. All targets are decided before the first connection.
- **Hard limits** on targets, ports per target, probes per run, concurrency, connection rate and
  time, with ceilings that cannot be raised.
- **`scan`**: a TCP connect scan with table, JSON, JSON Lines and CSV output, `--ports` (lists,
  ranges and the curated `common` preset), `--fail-on`, and `--output` that writes a file whole or
  not at all and never through a symbolic link.
- **Service inspection** of each open port: a passive banner read, one `HEAD /` request, and a TLS
  handshake that reads the leaf certificate without validating it. `--connect-only` turns this off.
- **Fingerprint rules** (nine built in) and **finding rules** (seven built in) in strict,
  validated YAML files, with `rules validate` to check a file. Every finding carries evidence.
- **`baseline save` and `baseline diff`**: a baseline of open ports and service names, and a drift
  report (new, closed, changed, not scanned) with exit code 1 on drift.
- **`demo`**: scans a lab of four services that it starts itself on loopback; needs no network.
- Hostile-input handling: byte, line and time caps on everything read from a service, and
  sanitising of control characters, escape sequences and bidirectional controls before anything is
  stored or shown; CSV cells that start with a formula character are defused.
- Documentation: [README](README.md), [docs/cli.md](docs/cli.md),
  [docs/architecture.md](docs/architecture.md), [docs/scope-policy.md](docs/scope-policy.md),
  [docs/ports.md](docs/ports.md), [docs/rules.md](docs/rules.md),
  [docs/threat-model.md](docs/threat-model.md), [docs/security-review.md](docs/security-review.md),
  [docs/performance.md](docs/performance.md), [SECURITY.md](SECURITY.md) and
  [CONTRIBUTING.md](CONTRIBUTING.md). Generated tables are checked against the code by tests.
