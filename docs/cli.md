# Command-line reference

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

```
network-scanner --version
network-scanner scan TARGET [TARGET ...] [options]
network-scanner baseline save TARGET [TARGET ...] --baseline PATH [options]
network-scanner baseline diff TARGET [TARGET ...] --baseline PATH [options]
network-scanner demo [--format FORMAT] [--output PATH] [--force]
network-scanner rules validate [--kind KIND] [PATH ...]
```

`network-scanner COMMAND --help` prints the options of a command. This page describes what they
mean. What the scanner puts on the wire is described in the README ("What the scanner sends");
why a target is accepted or refused is in [scope-policy.md](scope-policy.md).

## Targets

`TARGET` is one of: an IPv4 or IPv6 address, a CIDR block (`192.168.1.0/24`), an IPv4 range
(`192.168.1.10-20` or `192.168.1.10-192.168.1.20`), or a host name. At least one is required and
they may be mixed. The grammar is closed: anything it does not list is refused, including decimal,
hex, octal and short IPv4 forms, IPv4-mapped IPv6 addresses and CIDRs with host bits set.

- **Default scope** is loopback, RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6
  unique-local (`fc00::/7`) and IPv6 link-local (`fe80::/10`, the only range that takes a `%zone`).
- **Always refused**, whatever the options: multicast, broadcast, reserved, documentation and
  benchmark ranges, IPv4 link-local (`169.254.0.0/16`, which includes cloud metadata), `0.0.0.0/8`,
  and IPv6 forms that embed an IPv4 address.
- **Public addresses** (everything else, including `100.64.0.0/10`) need all of `--allow-public`,
  an entry in `--scope-file` that covers the address, and a confirmation (`--yes`, or typing `yes`
  at the prompt).
- A host name is resolved once, every answer is checked, and one refused answer refuses the whole
  name. The scan connects to the resolved addresses, never to the name.
- All targets are decided before the first connection. One refused target ends the run with exit
  code 2 and a reason code and scans nothing.
- The number of targets per run is capped (see "Limits"). A block is counted before it is expanded,
  so a `/8` is refused without being materialised.

The scope file is plain UTF-8 text, one IP address or CIDR per line, `#` starts a comment (its size
caps are in [scope-policy.md](scope-policy.md)). No host names. A public entry may be at most a `/24` (IPv4) or `/120` (IPv6).

## Ports

`--ports SPEC` (default `common`) is a comma-separated list of ports, ranges (`1-1024`) and the
preset name `common`, for example `22,80,8000-8100,common`. The number of distinct ports per target
is capped (see "Limits").
The `common` preset is a curated list of well-known service ports, not a ranking; it is listed in
[ports.md](ports.md).

## scan

```
network-scanner scan 192.168.1.0/28 --ports common --fail-on medium --format json --output scan.json
```

Connects to every (target, port), then inspects each open port (unless `--connect-only`), names
the service, and prints the report.

| Option | Meaning |
|--------|---------|
| `--ports SPEC` | Ports to scan. Default `common`. |
| `--allow-public` | One of the three requirements for public addresses. |
| `--scope-file PATH` | The scope file for public addresses. |
| `--yes` | Confirm public targets in advance (needed without a terminal). |
| `--concurrency N` | Simultaneous connections. |
| `--rate N` | Connection starts per second, shared by scan connections and probes. |
| `--connect-timeout SECONDS` | Timeout for each connection. On Windows a refused connection is reported only after the operating system's own retries, so a short timeout can report closed ports as filtered (see [performance.md](performance.md)). |
| `--total-timeout SECONDS` | Timeout for the whole run. |
| `--format {table,json,jsonl,csv}` | Output format. Default `table`. |
| `--output PATH` | Write the report to a new file instead of printing it. |
| `--force` | Let `--output` replace an existing file. |
| `--fail-on SEVERITY` | Exit with code 1 if a finding is at or above `info`, `low`, `medium`, `high` or `critical`. |
| `--connect-only` | Do not inspect open ports: connect, close, and send nothing. The report then has no services and no findings. |

Port states: `open` (the connection was established), `closed` (refused), `filtered` (no answer
within the timeout, or the network was unreachable) and `error` (anything else, such as a reset
while connecting). Closed ports are counted, not listed.

## baseline save

```
network-scanner baseline save 192.168.1.0/28 --baseline lab.json
```

Scans with inspection and writes the open ports and their service names to the baseline file. It
takes the target and limit options of `scan` (not `--connect-only`: a baseline always needs the
service names), `--baseline PATH` (required) and `--force` to replace an existing file. Nothing is
written unless the scan completed, because a partial scan would turn every port it missed into
"closed" later.

## baseline diff

```
network-scanner baseline diff 192.168.1.0/28 --baseline lab.json --fail-on high
```

Reads the baseline file first (it is untrusted input, and a bad file should fail before a scan),
scans with inspection, and reports:

- **new**: open now, not in the baseline;
- **closed**: in the baseline, probed now, not open;
- **changed**: open in both with a different service name (including unidentified versus
  identified);
- **not scanned**: in the baseline but not probed this time (for example because the targets or
  ports are narrower than when the baseline was made). Reported so it cannot be mistaken for
  "unchanged", but it is not drift.

Only service names are compared; see the Limitations in the README. `--format` is `table` or
`json`. Exit code 1 means drift was found, or a finding is at or above `--fail-on`. A scan that did
not complete gives no drift report, only its exit code. The tool does not schedule itself: run it
from cron, Task Scheduler or CI and act on the exit code.

## demo

```
network-scanner demo
```

Starts four small services on `127.0.0.1` (ports chosen by the operating system), scans and
inspects them, prints the report and stops them. It takes no target, so it cannot be pointed at
another host, and it needs no network. Ports differ on every run. It takes `--format`, `--output`
and `--force` like `scan`.

## rules validate

```
network-scanner rules validate [--kind {fingerprints,findings}] [PATH ...]
```

Checks fingerprint (default) or finding rule files against the schema. With no path, the built-in
rules are checked. See [rules.md](rules.md).

## Limits

These are the limits of a run. Defaults are what the command line uses. A ceiling is the largest
value the code accepts for that setting, and is a constant in the code, not a setting. A setting
that has no option is fixed at its default on the command line.

<!-- BEGIN GENERATED: limits -->
| Setting | Option | Default | Ceiling |
|---------|--------|---------|---------|
| `max_targets` | none | 256 | 4096 |
| `max_ports_per_target` | none | 1024 | 65535 |
| `concurrency` | `--concurrency` | 64 | 512 |
| `connections_per_second` | `--rate` | 100 | 1000 |
| `connect_timeout_s` | `--connect-timeout` | 3.0 | 30.0 |
| `banner_timeout_s` | none | 2.0 | 10.0 |
| `banner_max_bytes` | none | 1024 | 4096 |
| `total_timeout_s` | `--total-timeout` | 300.0 | 3600.0 |
| `probes_per_open_port` | none | 3 | 3 |
<!-- END GENERATED: limits -->

A run may also not exceed 100000 probes (targets times ports), which is a fixed bound. The fixed bounds on what is read
from a service, a rule file or a baseline file are in the table in
[architecture.md](architecture.md).

## Output

| Format | Contents |
|--------|----------|
| `table` | ASCII only. A port table (with a SERVICE column when ports were inspected), per-port details (banner, HTTP answer, TLS and certificate facts), findings most severe first with evidence and references, and a summary line. |
| `json` | The whole report, keys in model order, ASCII (non-ASCII text is written as `\u` escapes). |
| `jsonl` | One compact object per line with `type` first: `scan`, `target`, `result`, `observation`, `finding`. A record never contains a raw line break. |
| `csv` | One header, one `port` row per probed port and one `finding` row per finding, in the same columns. A text cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe, so a spreadsheet shows it as text. |

Text that came from the network was sanitised when it was captured and is sanitised again when
rendered, in every format. A string over a fixed length is cut. The report carries the time the
scan started; the baseline comparison ignores it.

`--output PATH` writes to a file instead of printing. UNC, URL and NUL paths are refused when the
command line is parsed. Windows device names (`NUL`, `COM1`, ...) and `/dev`, `/proc` and `/sys`
are refused. A symbolic link or Windows reparse point at the destination is refused, with or
without `--force`. An existing file is not replaced without `--force`, and this is checked before
the scan starts. The data is written to an exclusively created temporary file in the same
directory, synced, and then linked or renamed into place, so the file appears whole or not at
all. The README lists the one small race this leaves.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed; no drift (diff); no finding at or above `--fail-on` |
| 1 | `baseline diff` found drift, or a finding is at or above `--fail-on` |
| 2 | Usage error, scope refusal, unacceptable output path, unusable baseline or rule file |
| 3 | Runtime error, or the total timeout was reached (the report is partial) |
| 130 | Interrupted (the report is partial) |

An interrupted or timed-out run keeps its own code even if findings or drift were seen so far, and
its report says `complete: false` (JSON) or that it is partial (table).

## Confirmation prompt

When a plan contains public addresses (and `--yes` was not given), the tool lists them (at most ten
are shown) and asks you to type `yes`. It asks only when standard input is a terminal; without one
and without `--yes` the run is refused. Anything but `yes`, including end of input, declines and
exits with code 2. On Windows the `NUL` device reports itself as a terminal, so a run with input
redirected from it asks, reads end of input, and declines; it never proceeds.
