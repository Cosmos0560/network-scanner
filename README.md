# network-scanner

[![CI](https://github.com/Cosmos0560/network-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Cosmos0560/network-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

A defensive TCP connect scanner and attack-surface drift monitor for home labs and networks you
are authorized to test. It finds open TCP ports, names the service behind each one from what the
service says about itself, reports weak signals (cleartext protocols, certificate problems) with
the evidence for each, and compares a scan with a saved baseline so that a new or changed
service shows up as an exit code.

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

It is built to be safe to run and easy to check: the default scope is loopback and private
ranges, everything else is refused unless three separate conditions hold, every limit has a hard
ceiling, everything a scanned service sends is treated as hostile, and each safety claim below
links to the test or document that proves it.

What it is not: a vulnerability scanner, a stealth scanner, or an internet-wide scanner. See
[Limitations](#limitations).

## Contents

[Install](#install) - [Quick start](#quick-start) - [Commands](#commands) -
[Scope: what is scanned](#scope-what-is-scanned) - [What the scanner sends](#what-the-scanner-sends) -
[Findings and baselines](#findings-and-baselines) - [Architecture](#architecture) -
[Claims and evidence](#claims-and-evidence) - [Limitations](#limitations) - [Roadmap](#roadmap) -
[Documentation](#documentation) - [Development](#development)

## Install

Python 3.11 or newer. Two runtime dependencies, PyYAML and `cryptography` (the reasons are in
[docs/architecture.md](docs/architecture.md#dependencies)). The project is not published on PyPI;
install it from a checkout:

```
git clone https://github.com/Cosmos0560/network-scanner.git
cd network-scanner
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/network-scanner --version
```

On Windows the paths are `.venv\Scripts\python` and `.venv\Scripts\network-scanner`.

```
network-scanner 1.0.0
```

No administrator rights are needed or used: the scanner opens ordinary TCP connections and never
uses raw sockets.

## Quick start

`demo` starts four small services on `127.0.0.1` (ports chosen by the operating system), scans and
inspects them, prints the report and stops them. It needs no network and cannot be pointed at any
other host.

```
network-scanner demo
```

This is the output of one run. The ports, the time and the certificate hash differ on every run.

```
network-scanner 1.0.0  started 2026-10-08T08:31:14.828647+00:00
targets: 1  probes completed: 4

ADDRESS     PORT  STATE  SERVICE
127.0.0.1  53215  open   ssh (high)
127.0.0.1  53216  open   telnet (low)
127.0.0.1  53217  open   http (high)
127.0.0.1  53218  open   tls (high)

PORT DETAILS
127.0.0.1:53215
  banner: SSH-2.0-NetworkScannerLab_1.0
127.0.0.1:53216
  banner: ����   Network Scanner Lab (telnet-like)  login:
127.0.0.1:53217
  http: status 200, server NetworkScannerLab/1.0
127.0.0.1:53218
  tls: TLSv1.3, cipher TLS_AES_256_GCM_SHA384
  certificate: subject CN=network-scanner-lab; issuer CN=network-scanner-lab
  validity: 2026-10-07T08:31:14+00:00 to 2026-10-09T08:31:14+00:00; expired no
  names: DNS:localhost, IP:127.0.0.1, IP:::1
  facts: self-issued yes; signature verifies under own key yes; host name matches unknown
  sha256: dde1f4a86b50335b32eba86c2ea5f563e4b1d81a4f90e20e0e41adaa1dcf68b0

FINDINGS
[medium/low] cleartext-telnet 127.0.0.1:53216 - Telnet service (remote login without encryption)
    evidence: 127.0.0.1:53216 looks like telnet (fingerprint rule telnet-login-prompt, confidence low). Banner: ����   Network Scanner Lab (telnet-like)  login:
    references: CWE-319, RFC 854
[info/high] tls-certificate-self-issued 127.0.0.1:53218 - Certificate is self-issued (issuer equals subject)
    evidence: 127.0.0.1:53218 subject CN=network-scanner-lab, issuer CN=network-scanner-lab; signature verifies under its own key: yes
    references: RFC 5280

open: 4  closed: 0  filtered: 0  error: 0
findings: 2 (medium: 1, info: 1)
```

How to read it:

- Each open port got a **service** name and, in brackets, a **confidence**. The confidence says
  how strongly the evidence points at that name; it is not a severity. Telnet is `low` because many
  services print a `login:` prompt.
- The telnet-like service starts with the Telnet option bytes `FF FD 18 FF FD 20`. They are not
  valid UTF-8, so decoding replaced four of them with U+FFFD and the sanitiser dropped the control
  byte `18`; the ASCII-only output shows each U+FFFD as `�`. This is the sanitiser working
  on data from the network, not a bug in the display.
- A **finding** says what rule fired, how much it would matter (**severity**), how sure the
  evidence makes us, and the evidence. The certificate is reported as *self-issued*, which is a
  fact about its names; the scanner does not validate certificates.
- The exit code was 0: no drift was asked for and no `--fail-on` threshold was given.

## Commands

Everything is documented in [docs/cli.md](docs/cli.md); `network-scanner COMMAND --help` prints the
options. Exit codes: 0 completed and clean; 1 drift found, or a finding at or above `--fail-on`;
2 usage error or scope refusal; 3 runtime error or total timeout; 130 interrupted. A run that is
interrupted or times out prints a partial report that says so.

| Command | What it does |
|---------|--------------|
| `network-scanner --version` | Prints the version. |
| `network-scanner scan TARGET...` | Connect scan, then inspection of each open port, then services and findings. |
| `network-scanner baseline save TARGET... --baseline FILE` | Scans and writes the open ports and service names to FILE. |
| `network-scanner baseline diff TARGET... --baseline FILE` | Scans and reports what is new, closed or changed since FILE. Exit code 1 on drift. |
| `network-scanner demo` | Scans a lab of four services that it starts itself on loopback. |
| `network-scanner rules validate [--kind KIND] [PATH...]` | Checks fingerprint or finding rule files against the schema. |

### scan

```
network-scanner scan 192.168.1.0/24 --ports common --fail-on medium
network-scanner scan 10.0.0.5 --ports 22,80,8000-8100 --format json --output report.json
network-scanner scan 10.0.0.5 --connect-only
```

Targets are IP addresses, CIDR blocks, IPv4 ranges and host names. `--ports` takes ports, ranges
and the curated `common` preset. `--format` is `table`, `json`, `jsonl` or `csv`. `--output` writes
a new file whole or not at all, never through a symbolic link, and `--force` lets it replace a
file. `--fail-on SEVERITY` turns findings into exit code 1. `--connect-only` skips inspection (see
[What the scanner sends](#what-the-scanner-sends)). `--concurrency`, `--rate`, `--connect-timeout`
and `--total-timeout` lower or raise a limit up to its ceiling.

Here is a lab like the one above (another run, so other ports), scanned with `--connect-only`.
The four ports were listening when the command ran:

```
network-scanner scan 127.0.0.1 --ports 59741,59742,59743,59744 --connect-only
```

```
network-scanner 1.0.0  started 2026-10-08T08:31:27.972456+00:00
targets: 1  probes completed: 4

ADDRESS     PORT  STATE
127.0.0.1  59741  open
127.0.0.1  59742  open
127.0.0.1  59743  open
127.0.0.1  59744  open

open: 4  closed: 0  filtered: 0  error: 0
```

No service names and no findings: nothing was read from the ports.

### baseline save and baseline diff

A baseline is a small JSON file of the open ports and their service names. `baseline diff` scans
again and reports:

- **new**: open now, not in the baseline;
- **closed**: in the baseline, probed now, not open;
- **changed**: open in both with a different service name;
- **not scanned**: in the baseline but not probed this time (narrower targets or ports). This is
  reported so that it cannot be mistaken for "unchanged", but it is not drift.

The example below was run against three throwaway listeners on loopback that each send one line
and close: an FTP-style greeting on 59287, a POP3-style greeting on 59289, and nothing on 59288.

```
network-scanner baseline save 127.0.0.1 --ports 59287,59288,59289 --baseline lab.json
```

```
baseline saved: 2 open port(s) -> lab.json
```

Nothing changed, so `baseline diff` with the same arguments exits with code 0:

```
baseline diff: no drift
new: 0  closed: 0  changed: 0  not scanned: 0

findings in this scan: 1 (low: 1)
  [low/medium] cleartext-ftp 127.0.0.1:59287
```

Then the listener on 59289 was stopped, the one on 59287 was replaced by an SSH-style greeting,
and a new FTP-style listener was started on 59288. The same command now exits with code 1:

```
baseline diff: drift found
new: 1  closed: 1  changed: 1  not scanned: 0

NEW          127.0.0.1:59288 (ftp)
CLOSED       127.0.0.1:59289 (pop3)
CHANGED      127.0.0.1:59287 ftp -> ssh

findings in this scan: 1 (low: 1)
  [low/medium] cleartext-ftp 127.0.0.1:59288
```

Scanning only part of the baseline's ports reports the rest as not scanned, not as closed:

```
network-scanner baseline diff 127.0.0.1 --ports 59287 --baseline lab.json
```

```
baseline diff: drift found
new: 0  closed: 0  changed: 1  not scanned: 1

CHANGED      127.0.0.1:59287 ftp -> ssh
NOT SCANNED  127.0.0.1:59289 (pop3)
```

`baseline save` will not replace an existing file without `--force`, writes nothing from a scan
that did not complete, and `baseline diff` produces no drift report from one either. The baseline
file is read back as untrusted input and checked before the scan starts. The tool does not run on
a schedule: run `baseline diff` from cron, Task Scheduler or CI and act on the exit code.

### rules validate

```
network-scanner rules validate
network-scanner rules validate --kind findings
```

```
OK: built-in fingerprint rules (9 rules)
OK: built-in finding rules (7 rules)
```

With a path it checks the file you give it against the same strict schema the built-in rules pass.
The scanner itself uses only the built-in rules; see [docs/rules.md](docs/rules.md).

## Scope: what is scanned

The tool refuses by default. [docs/scope-policy.md](docs/scope-policy.md) has the full grammar,
the address-class table and every reason code. In short:

- **Scanned by default:** loopback, RFC 1918 private ranges, IPv6 unique-local and IPv6 link-local.
- **Public addresses** (everything else, including `100.64.0.0/10`) need all three of
  `--allow-public`, an entry in `--scope-file` that covers the address, and a confirmation
  (`--yes`, or typing `yes` at the prompt; without a terminal and without `--yes` the run is
  refused).
- **Always refused**, whatever the options: multicast, broadcast, reserved, documentation and
  benchmark ranges, IPv4 link-local (`169.254.0.0/16`, which holds cloud metadata addresses),
  `0.0.0.0/8`, ambiguous numeric forms (decimal, hex, octal, short) and IPv6 forms that embed an
  IPv4 address.
- **Host names** are resolved once, every answer is checked, and one bad answer refuses the whole
  name. The scan connects to the resolved address, never to the name.
- **All targets are decided before the first connection.** One refused target ends the run with
  exit code 2 and a reason code, and nothing is scanned.

Real refusals (nothing was connected to in any of these):

```
network-scanner scan 2130706433 --ports 22
refused: ambiguous_numeric: decimal, hex, octal and short IPv4 forms are ambiguous; use a.b.c.d (target: '2130706433')
```

```
network-scanner scan 203.0.113.5 --ports 22
refused: always_refused: 203.0.113.5 is in class documentation (target: '203.0.113.5')
```

```
network-scanner scan 100.64.0.1 --ports 22
refused: public_not_allowed: 100.64.0.1 is in class public (target: '100.64.0.1')
```

```
network-scanner scan ::ffff:10.0.0.1 --ports 22
refused: embedded_ipv4: ::ffff:a00:1 is in class embedded_ipv4 (target: '::ffff:10.0.0.1')
```

```
network-scanner scan 192.168.1.5/24 --ports 22
refused: cidr_host_bits: host bits are set; write the network address (target: '192.168.1.5/24')
```

```
network-scanner scan 10.0.0.0/8 --ports 22
refused: too_many_targets: more than 256 targets (target: '10.0.0.0/8')
```

Each of these exited with code 2.

## What the scanner sends

This is everything the scanner puts on the wire to a target, so you can check it against your
authorization and your intrusion detection. Each probe is its own TCP connection, made through the
same policy check as the scan and paced by the same rate limiter.

1. **The scan: a TCP connect.** For every (address, port) the scanner asks the operating system to
   connect. If the connection is established the port is `open`, and the scanner closes it at once.
   **No application data is sent.** A refused connection is `closed`; no answer within the timeout
   (or an unreachable network) is `filtered`.
2. **Banner read** (a second connection, made for each open port). **Sends nothing.** It listens
   for what the service says unprompted: at most 1024 bytes, ending at the first line break, at
   end of stream, or when 2 seconds have passed, whichever comes first. Services that speak first
   (SSH, FTP, SMTP, POP3, IMAP, VNC) are identified here and are never sent anything.
3. **HTTP `HEAD /`** (a third connection, only if the banner read got nothing). Exactly this request
   is sent, with every line ended by CR LF and followed by one empty line:

   ```
   HEAD / HTTP/1.1
   Host: <host>:<port>
   User-Agent: network-scanner/<version>
   Accept: */*
   Connection: close
   ```

   `<host>` is the host name if the target was given as a host name, otherwise the IP address
   (an IPv6 address in brackets, without a zone id), checked against a strict character set;
   `<version>` is this tool's version (`1.0.0`). There is no body, no credential, no cookie and no
   other method, and redirects are not followed. The response head is read up to a fixed number of
   bytes and header lines and a deadline, and the body is never read.
4. **TLS handshake** (another connection, only if nothing has answered yet; on ports that are
   normally TLS from the first byte, such as 443, 465, 636, 993 and 8443, it is tried before the
   `HEAD`). A TLS ClientHello is sent and the handshake is completed. The scanner sets only the
   lowest version it offers (**TLS 1.2**), turns certificate and host-name verification off so
   that it can see whatever certificate a service presents, and sends a server name (SNI) **only
   when the target was given as a host name**. Everything else in the ClientHello (cipher suites,
   extensions, the highest version) is the default of Python's `ssl` module and the OpenSSL it was
   built against. **Nothing is sent after the handshake**; the leaf certificate is read and the
   connection is closed.

The probes run in turn and stop as soon as one is answered. At most three are made per open port, so
one open port sees at most four connections from the scanner: the scan and three probes. Nothing the scanner sends depends on what the service said, and no probe
authenticates, guesses a password or exploits anything.

Two more things that are not connections to the target:

- a **host name** is resolved once through the operating system's resolver, so your DNS server sees
  the query;
- `baseline`, `--output` and the scope file are local files; the scanner never contacts any other
  host.

**What `--connect-only` turns off.** All three probes: the banner read, the `HEAD` request and the
TLS handshake. With `--connect-only` the scanner makes only the connections of step 1 and sends
nothing. The report then has no service names, no banners, no certificates and no findings. The
`baseline` commands do not take it, because a baseline is made of service names.

Two consequences worth knowing:

- A service that speaks first but slowly (the banner deadline is 2 seconds) is treated as silent,
  and will then also receive the `HEAD` request and a TLS handshake attempt.
- On a port that is TLS but not one of the usual TLS ports, the plain-text `HEAD` request is sent
  before the TLS handshake. The TLS server sees it as garbage and the handshake probe then
  identifies the port.

Evidence: [docs/architecture.md](docs/architecture.md#fingerprinting-and-tls-phase-4),
[tests/test_probes.py](tests/test_probes.py), [tests/test_inspect.py](tests/test_inspect.py),
[tests/test_cli_phase5.py](tests/test_cli_phase5.py).

## Findings and baselines

The built-in rules and the structure of a rule file are in [docs/rules.md](docs/rules.md). A
finding is a weak signal with evidence, not a verdict: cleartext Telnet or FTP, a deprecated TLS
version, an expired certificate, a certificate that does not cover the requested name, a
self-issued certificate, a certificate that could not be read. They carry no vulnerability data, no
product versions and no ATT&CK mapping (an open port is not an observed technique). References are
CWE ids and RFC numbers, only where precise.

## Architecture

```
layer  package(s)              role
7  cli                       - argument parsing, prompts, exit codes
6  lab                       - the loopback services used by `demo` and the tests
5  baseline, output          - baseline file and diff; table, JSON, JSON Lines, CSV
4  fingerprint, findings     - pure decisions: observation -> service -> findings
3  engine                    - scan orchestration through interfaces: concurrency, timeouts
2  net, rules                - sockets, TLS, DNS adapters; YAML rule loading and validation
1  scope, ports              - target grammar, address classes, scope policy, port specs
0  core                      - data model, errors, sanitiser, limits, interfaces
```

A module imports only from its own layer or a lower one. Only `net`, `lab` and `cli` touch
sockets, clocks or randomness; everything above `net` receives a connector, resolver, clock and
sleeper through interfaces, which is what makes decision logic deterministic and testable. An
AST-based check enforces this and runs in the gate and inside the test suite. Details, the reason
for each dependency and the design decisions: [docs/architecture.md](docs/architecture.md).

## Claims and evidence

Every row names a claim this README makes about the tool and the test or document that supports
it. Nothing is claimed without a row. "Test" means a test that runs in the project's gate.

| Claim | Evidence |
|-------|----------|
| By default only loopback, RFC 1918, IPv6 unique-local and IPv6 link-local are scanned. | [scope-policy.md](docs/scope-policy.md#decisions); [test_scope_policy.py](tests/test_scope_policy.py) (`test_the_default_scope_is_allowed_whatever_the_options`) |
| A public address needs `--allow-public`, a scope-file entry and a confirmation. | [test_scope_policy.py](tests/test_scope_policy.py) (`test_public_targets_need_all_three_conditions`); [test_cli_scan.py](tests/test_cli_scan.py) (`test_public_targets_need_the_flag_and_the_scope_file`, `test_without_a_terminal_public_targets_need_yes`) |
| Multicast, broadcast, reserved, documentation, benchmark and IPv4 link-local addresses are refused whatever the options. | [test_scope_policy.py](tests/test_scope_policy.py) (`test_always_refused_addresses_stay_refused_with_every_option`); [test_scope_classify.py](tests/test_scope_classify.py) |
| Ambiguous numeric forms and IPv6 forms that embed IPv4 are refused. | [test_scope_parser.py](tests/test_scope_parser.py); [test_scope_policy.py](tests/test_scope_policy.py) (`test_every_bypass_is_refused_with_its_reason_code`) |
| A host name is resolved once and pinned; one bad answer refuses the whole name; the scan connects to the pinned address. | [test_scope_policy.py](tests/test_scope_policy.py) (`test_one_bad_answer_refuses_the_whole_hostname`, `test_a_hostname_is_resolved_once_pinned_and_sorted`); [test_cli_scan.py](tests/test_cli_scan.py) (`test_a_hostname_is_resolved_and_the_pinned_address_is_scanned`) |
| All targets are decided before the first connection; one refusal scans nothing. | [test_e2e.py](tests/test_e2e.py) (`test_a_refused_target_opens_no_connection_at_all`); [test_cli_scan.py](tests/test_cli_scan.py) (`test_one_bad_target_among_good_ones_refuses_the_whole_run`) |
| Every connection passes the policy again, and only one module may connect. | [test_net.py](tests/test_net.py) (`test_the_connector_refuses_unapproved_addresses_before_opening_a_socket`); [test_architecture.py](tests/test_architecture.py) (`test_the_real_connector_is_the_only_module_that_connects`) |
| Targets, ports, probes, concurrency, rate and time are capped, with ceilings that cannot be raised. | [cli.md](docs/cli.md#limits); [test_limits_errors.py](tests/test_limits_errors.py); [test_scope_policy.py](tests/test_scope_policy.py) (`test_the_target_cap_is_exact`); [test_cli_scan.py](tests/test_cli_scan.py) (`test_too_many_probes_are_refused_before_any_connection`) |
| The probes send only what "What the scanner sends" says, and `--connect-only` sends nothing after connecting. | [test_probes.py](tests/test_probes.py) (`test_the_request_is_one_fixed_head_request`); [test_cli_phase5.py](tests/test_cli_phase5.py) (`test_connect_only_sends_nothing_after_connecting`); [test_inspect.py](tests/test_inspect.py) (`test_a_service_that_speaks_first_is_identified_with_one_connection_and_sent_nothing`) |
| An open port gets at most three probe connections. | [test_inspect.py](tests/test_inspect.py) (`test_the_probe_limit_is_honoured`); [test_fingerprint_e2e.py](tests/test_fingerprint_e2e.py) (`test_each_open_port_gets_at_most_the_configured_number_of_connections`) |
| Reads from a service are bounded in bytes, lines and time: endless banners, slow drips, silence and resets do not hang or exhaust the scan. | [test_probes.py](tests/test_probes.py); [test_fingerprint_e2e.py](tests/test_fingerprint_e2e.py); [test_net.py](tests/test_net.py); hostile servers in [tests/hostile.py](tests/hostile.py) |
| Text from the network (ANSI sequences, CR/LF, NUL, bidirectional controls, invalid UTF-8) is sanitised before it is stored or shown. | [test_sanitize.py](tests/test_sanitize.py); [test_output_formats.py](tests/test_output_formats.py); [test_fingerprint_e2e.py](tests/test_fingerprint_e2e.py) |
| CSV cells cannot start a spreadsheet formula, and JSON Lines records cannot gain lines. | [test_output_formats.py](tests/test_output_formats.py) (`test_cells_starting_with_a_formula_character_are_defused`, `test_jsonl_hostile_text_cannot_add_lines_or_survive`) |
| A malformed, truncated or oversized certificate cannot crash the reader. | [test_certificate.py](tests/test_certificate.py); [test_tls.py](tests/test_tls.py) |
| Certificates are read, not validated; "self-issued" and "signature verifies under its own key" are separate facts. | [architecture.md](docs/architecture.md#certificates-decisions-d1-d2-and-d6); [test_certificate.py](tests/test_certificate.py) (`test_names_that_say_self_issued_do_not_make_the_signature_verify`); [test_tls.py](tests/test_tls.py) |
| Rule files are loaded with safe YAML, a closed schema and a restricted regular-expression subset. | [rules.md](docs/rules.md); [test_rules.py](tests/test_rules.py); [test_regex_safety.py](tests/test_regex_safety.py); [test_yamlsafe.py](tests/test_yamlsafe.py); measured worst cases in [performance.md](docs/performance.md) |
| Every finding carries evidence, and each built-in finding rule has a positive and a negative test. | [test_findings.py](tests/test_findings.py) (`test_every_built_in_rule_has_a_positive_and_a_negative_case`, `test_every_finding_carries_evidence_and_keeps_severity_and_confidence_apart`) |
| The baseline file is read as untrusted input; drift is new, closed, changed and not scanned. | [test_baseline.py](tests/test_baseline.py); [test_cli_phase5.py](tests/test_cli_phase5.py) (`test_new_closed_and_changed_ports_are_drift_with_exit_code_one`, `test_a_bad_baseline_file_fails_with_exit_code_two_before_any_connection`) |
| A scan that did not complete writes no baseline and gives no drift report. | [test_cli_phase5.py](tests/test_cli_phase5.py) (`test_an_incomplete_scan_writes_no_baseline`, `test_an_incomplete_scan_gives_no_drift_report`) |
| Report files appear whole or not at all, are never written through a symbolic link, and do not replace a file without `--force`. | [test_output_files.py](tests/test_output_files.py); [test_cli_phase5.py](tests/test_cli_phase5.py) |
| Exit codes are as documented, and an interruption prints a partial report. | [cli.md](docs/cli.md#exit-codes); [test_docs_drift.py](tests/test_docs_drift.py); [test_cli_scan.py](tests/test_cli_scan.py) (`test_the_scan_status_decides_the_exit_code_and_the_report_is_still_printed`) |
| The demo touches only loopback and takes no target. | [test_cli_phase5.py](tests/test_cli_phase5.py) (`test_the_demo_connects_only_to_loopback_and_never_to_port_8080`, `test_the_demo_takes_no_target`); [test_lab.py](tests/test_lab.py) |
| The code is layered, only `net`, `lab` and `cli` do I/O, and there are no import cycles. | [scripts/check_architecture.py](scripts/check_architecture.py); [test_architecture.py](tests/test_architecture.py); [architecture.md](docs/architecture.md#layers) |
| Tests leak no sockets, tasks or unawaited coroutines. | [test_leak_detection.py](tests/test_leak_detection.py); `filterwarnings = ["error"]` in [pyproject.toml](pyproject.toml) |
| Timing-dependent logic is tested on virtual time, not by sleeping. | [tests/virtual_loop.py](tests/virtual_loop.py); [test_engine.py](tests/test_engine.py); [architecture.md](docs/architecture.md#scanning-phase-3) |
| Operating-system error codes are normalised the same way on Linux and Windows. | [test_net.py](tests/test_net.py) (`test_windows_error_numbers_are_normalised_on_every_platform`) |
| No key or certificate is committed, and no tracked file holds a hidden or bidirectional character. | [test_no_committed_keys.py](tests/test_no_committed_keys.py); [test_no_hidden_characters.py](tests/test_no_hidden_characters.py) |
| The documented tables, limits and exit codes match the code. | [test_docs_drift.py](tests/test_docs_drift.py) |
| The version is one value everywhere it appears. | [test_release.py](tests/test_release.py) |
| Lint, formatting, type checks for Linux and Windows, the architecture check and a coverage threshold run before every commit and in CI. | [scripts/gate.py](scripts/gate.py); [test_gate.py](tests/test_gate.py); [.github/workflows/ci.yml](.github/workflows/ci.yml) |
| The release was built, installed into a clean environment and audited. | [security-review.md](docs/security-review.md) |
| Threats considered, and what is not defended against. | [threat-model.md](docs/threat-model.md) |

## Limitations

Read these before relying on a result.

**What it does not do**

- **TCP connect only.** No UDP, no SYN or other raw-packet scanning, no OS fingerprinting, no CVE
  or vulnerability matching, no credential testing, no crawling, no distributed scanning.
- **It is not a vulnerability scanner.** Findings are weak signals with evidence. Service names are
  protocol names, not products or versions. No finding means "none of the built-in finding rules fired", not "secure".
- **It does not run itself.** There is no daemon or scheduler. Drift monitoring means running
  `baseline diff` from something that does.
- **Limits are fixed on the command line.** One run covers at most 256 targets and 1024 ports per
  target. A larger network needs several runs.

**TLS and certificates**

- **TLS 1.2 is the minimum offered.** A server that speaks only TLS 1.1 or older fails the
  handshake and shows up as an open port with no certificate, not as a deprecated-version
  finding. That finding can fire end to end only for a server that negotiates an older version
  despite the offer, and is otherwise tested on synthetic data. The scanner also does not test
  whether a TLS 1.3 server additionally accepts older versions.
- **Only the leaf certificate is read.** No chain is read or built.
- **Reading a certificate is not validating it.** There is no trust store, no revocation check and
  no chain validation. "Self-issued" says issuer equals subject; "signature verifies under its own
  key" says exactly that; neither says the certificate should be trusted.
- **An HTTPS port is named `tls`.** The HTTP `Server` header is read only over plain HTTP, and the
  protocol inside TLS is not probed.

**Fingerprinting**

- **Few protocols.** Only SSH, VNC, HTTP, TLS, FTP, SMTP, POP3, IMAP and Telnet can be named
  ([docs/rules.md](docs/rules.md)). Any other service, or one that waits for the client and is
  neither HTTP nor TLS, is reported as open with no service. A service can lie about itself; so
  can its banner.
- **Rule files are validated but not loadable.** `rules validate` checks a rule file; `scan` and
  `baseline` use only the built-in rules.
- **The regular-expression check is structural, not a proof of linear time.** It rejects patterns
  that are known to backtrack badly and caps the input a pattern sees. The worst accepted patterns
  that were tried are timed in [docs/performance.md](docs/performance.md); other patterns, Python
  versions and `re` builds were not measured.

**Baselines and output**

- **`baseline diff` compares service names only.** A changed certificate, banner or `Server`
  header on the same service name is not drift. A port that became open, closed or changed its
  service name is. `baseline diff --format` offers `table` and `json`.
- **A small check-then-rename race on POSIX.** `--output` and `baseline save` normally publish the
  finished file with a hard link, which fails if the name exists, so there is no gap. On a file
  system without hard links they check and then rename, and on POSIX a rename replaces a file
  that appeared in between. Windows refuses to rename onto an existing file. With `--force` the
  replacement is intended. A symbolic link at the destination is always refused.
- **Reports are plain files.** They are neither encrypted nor signed, and list what is open on
  your network.

**Names and DNS**

- **DNS is resolved once and pinned.** A name whose answers change during the run is scanned at the
  addresses it had at the start. The resolver is the operating system's, so a hostile resolver can
  point a name at a different allowed address (for example another host on the same private
  network), though never at a refused range. A name with more than 8 answers is refused, not
  truncated.
- **The address classification is a fixed table.** It is not updated from the IANA registries;
  keeping it current is a manual task. A zone id is checked for form only, not against the
  machine's interfaces.

**Platforms and timing**

- **Windows reports a refused connection slowly.** A connection to a closed port is refused only
  after the operating system's own retries. The default connect timeout (3 seconds) was chosen
  with that margin, and a shorter one can report closed ports as `filtered`. The delay was
  measured on one Windows 11 machine; nothing was measured on Linux, and no claim is made about
  Linux timing ([docs/performance.md](docs/performance.md)).
- **On Windows, `NUL` looks like a terminal.** With input redirected from it, a run that needs a
  confirmation asks, reads end of input, and declines. It never proceeds, so this fails closed.
- **Development and tests ran on Windows with Python 3.13.** Linux and Python 3.11 and 3.12 are
  exercised only by CI, whose results this README does not report. The tests that need a
  symbolic link are skipped on an account that cannot create one; CI runs them on Linux.
- **The `cryptography` lower bound is a statement about the API used**, not a tested
  configuration. Only the newest release is installed by the tests and by CI.

**Not verified**

- **Real dropped packets.** `filtered` is tested through an injected connector; it cannot be
  produced on loopback without firewall rules.
- **A real DNS server.** Every test uses a fake resolver; the system resolver adapter is exercised
  through an injected lookup.
- **A real Ctrl+C in a console on both operating systems.** Interruption is tested in-process with
  a raised signal, which exercises the same interrupt path but not a terminal.
- **Behaviour against real servers.** All end-to-end tests run against the lab and hostile servers
  on loopback; no non-loopback host was contacted during development, so how the probes behave
  against real SSH, HTTP or TLS servers is not verified.
- **Continuous integration.** The workflow file was checked for deprecated actions from its text
  alone, which is not enough to know; see [docs/security-review.md](docs/security-review.md).

## Roadmap

Out of scope for 1.0, and not promised: UDP scanning, raw SYN or stealth scanning, OS
fingerprinting, vulnerability or CVE matching, credential testing, web crawling, distributed
scanning and a graphical interface.

## Documentation

| Document | What it covers |
|----------|----------------|
| [docs/cli.md](docs/cli.md) | Every command and option, limits, output formats, exit codes |
| [docs/scope-policy.md](docs/scope-policy.md) | Target grammar, address classes, decisions, reason codes |
| [docs/ports.md](docs/ports.md) | Port specifications and the `common` preset |
| [docs/rules.md](docs/rules.md) | Rule files and the built-in rules |
| [docs/architecture.md](docs/architecture.md) | Layers, decisions, dependencies, how a scan works |
| [docs/threat-model.md](docs/threat-model.md) | Assets, actors, threats, mitigations, residual risks |
| [docs/security-review.md](docs/security-review.md) | Release checks and accepted findings |
| [docs/performance.md](docs/performance.md) | The only place measured numbers appear |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to build, test and contribute |
| [PLAN.md](PLAN.md) | The approved plan, with its decisions in section 0 |

## Development

```
uv venv --python 3.13 .venv
uv pip install -e ".[dev]"
python scripts/gate.py
```

The gate runs ruff, mypy (Linux and Windows platform settings), the architecture check and pytest
with a coverage threshold. CI runs it on Ubuntu and Windows with Python 3.11, 3.12 and 3.13. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). Author: Otabek Yakubov.
