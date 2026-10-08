# Threat model

> **Legal notice.** Scan only networks you own or have written permission to scan.
> Unauthorized scanning can be illegal.

This page says what network-scanner protects, from whom, how, and what it does not try to protect.
Each mitigation points at the test or document that shows it; the README repeats the main ones in
its claim-to-evidence table. A mitigation listed here is a design decision with tests, not a proof.

## What the tool is

A command-line program that a person runs on their own machine against targets they choose. It
opens TCP connections to those targets, reads some bytes back, and prints or saves a report. It is
not a service, takes no input from other users, and has no privileges beyond a normal user's: no
raw sockets and no administrator rights.

## Assets

1. **Third parties' machines and networks.** The tool must not become a way to probe, flood or
   fingerprint hosts nobody authorised it to touch.
2. **The machine running the tool**, and the person at its terminal, from whatever the scanned
   services, DNS servers, files and arguments send it.
3. **The integrity of the report.** A baseline and a drift report are only useful if a hostile
   target cannot forge what they say or smuggle content into them.
4. **The user's files.** Writing a report or a baseline must not overwrite or follow something it
   should not.

## Actors

- **The operator**, who is trusted to be authorised for the targets they name but can make
  mistakes (a typo, a wrong CIDR, a pasted number in an odd format).
- **A hostile or compromised service** on a scanned host: it controls every byte it sends back and
  how it behaves (silence, flood, drip, reset, garbage TLS, a malicious certificate).
- **A hostile or compromised DNS server** (or anyone able to alter DNS answers) for a host name
  given as a target.
- **A supplier of files**: a scope file, a rule file or a baseline file that someone else wrote.
- **An attacker with limited write access** to the directory the report goes to.
- **A consumer of the output**: a terminal, a log pipeline or a spreadsheet that will render what
  the tool wrote.

## Trust boundaries

Everything that arrives from a network, from DNS, or from a file is untrusted. The only trusted
inputs are the command line the operator typed, the package's own code and built-in rule files. Even
the command line is validated, because a mistake there is the most likely failure.

## Threats and mitigations

| # | Threat | Mitigation | Evidence |
|---|--------|------------|----------|
| T1 | The operator scans something they should not: a public host, a cloud metadata address, a multicast or broadcast address, a whole `/8`. | Default scope is loopback, RFC 1918, IPv6 unique-local and link-local. Always-refused ranges cannot be overridden. A public address needs the flag, a scope-file entry and a confirmation. Counts are computed before expansion and capped. | [scope-policy.md](scope-policy.md); `tests/test_scope_policy.py`, `tests/test_scope_classify.py` |
| T2 | An address written so that two parsers disagree (`2130706433`, `0x7f.0.0.1`, `010.0.0.1`, `::ffff:10.0.0.1`) slips past the policy or is read differently by the connection call. | A closed grammar parsed by the project's own code, not by `ipaddress` or `socket`; ambiguous numeric and embedded-IPv4 forms are refused; the connector accepts only plain IP literals and connects with `AI_NUMERICHOST`. | `tests/test_scope_parser.py`, `tests/test_net.py` (`test_the_connector_accepts_only_plain_ip_literals`) |
| T3 | A host name that resolves to a mix of allowed and refused addresses, or that resolves differently between the check and the connection (DNS rebinding). | Resolved once; every answer is checked; one bad answer refuses the name; the scan connects to the pinned addresses, never the name; the connector re-checks the policy for every connection. | `tests/test_scope_policy.py` (mixed answers, answer cap, garbage answers) |
| T4 | A code path opens a connection without going through the policy. | Only `net/connector.py` may connect, enforced by the architecture check on the source; the connector re-checks the policy itself. | `scripts/check_architecture.py`, `tests/test_architecture.py`, `tests/test_net.py` |
| T5 | The tool becomes a flooding or resource-exhaustion tool against the targets, or against the operator's own machine. | Hard caps on targets, ports, probes per run, concurrency, connection rate and time, with ceilings that cannot be raised; at most three probe connections per open port; probes share the scan's rate limiter and concurrency bound. | [cli.md](cli.md) (Limits); `tests/test_limits_errors.py`, `tests/test_engine.py`, `tests/test_inspect.py` |
| T6 | A hostile service sends an endless banner, drips one byte at a time, never answers, or resets mid-read, to exhaust memory or hang the scan. | Every read has a byte cap, a line cap and one deadline for the whole read; nothing is read until end of stream; every probe has its own deadline; a connection that does not close politely is aborted. | `tests/test_probes.py`, `tests/test_fingerprint_e2e.py`, `tests/test_net.py`, `tests/hostile.py` |
| T7 | A hostile service sends terminal escape sequences, carriage returns, NUL bytes, bidirectional controls or invalid UTF-8 so that the report lies or the terminal is controlled. | All network text is sanitised when captured and again when rendered, in every format; output is ASCII; rendering is tested with every text field hostile. | `tests/test_sanitize.py`, `tests/test_output_formats.py`, `tests/test_fingerprint_e2e.py` |
| T8 | Report fields that start with `=`, `+`, `-` or `@` run as formulas when the CSV is opened in a spreadsheet. | Such cells get a leading apostrophe. | `tests/test_output_formats.py` |
| T9 | A malicious certificate (truncated, oversized, corrupted, with huge or hostile names) crashes or confuses the parser. | A size cap before parsing; parsing in the `cryptography` library, not in a hand-written parser; any failure becomes a fixed error code; names are capped and sanitised. | `tests/test_certificate.py`, `tests/test_tls.py` |
| T10 | A certificate is taken for a statement of trust. | The scanner reads the certificate and reports facts. It builds no chain and consults no trust store, and no output says "valid" or "trusted". | [architecture.md](architecture.md) ("Certificates"); `tests/test_tls.py` |
| T11 | A hostile rule file, scope file or baseline file: a YAML bomb, aliases, tags, duplicate keys, a regular expression that backtracks catastrophically, an enormous file. | Size caps before parsing; `yaml.safe_load` only, after a check that refuses anchors, aliases, explicit tags, duplicate keys and deep nesting; closed schemas; a restricted regular-expression subset with a cost budget and an input cap; a strict baseline reader that names the place of an error. | `tests/test_yamlsafe.py`, `tests/test_rules.py`, `tests/test_regex_safety.py`, `tests/test_baseline.py`, `tests/test_ports_presets.py` |
| T12 | A hostile command line: NUL bytes, UNC paths, URLs, device names, enormous values. | Paths are checked when the command line is parsed; numbers are bounded; argument errors are sanitised before they are echoed. | `tests/test_cli_scan.py`, `tests/test_cli.py` |
| T13 | `--output` or `--baseline` is pointed at a symbolic link, a device or an existing file, or a link is planted between the check and the write. | A link at the destination is refused; the data goes to an exclusively created temporary file in the same directory and is linked or renamed into place, so a planted link is replaced, not followed; no overwrite without `--force`. A small race remains on a POSIX file system without hard links (see the README). | `tests/test_output_files.py` |
| T14 | Probes send something dangerous or something that depends on what the service said (an injection into a service). | The three probes send nothing, one fixed `HEAD /` request, and a TLS handshake. The request template has two validated inputs; nothing sent depends on a response. | `tests/test_probes.py` (`test_the_request_is_one_fixed_head_request`), `tests/test_cli_phase5.py` (`test_connect_only_sends_nothing_after_connecting`) |
| T15 | A secret ends up in the repository or the release: a private key, a certificate, an e-mail address. | Test certificates are generated at runtime into a temporary directory that is deleted at once; key and certificate file types are ignored by git and a test fails if one is tracked. | `tests/test_no_committed_keys.py` |
| T16 | Source or documentation that reads differently from what it does, through bidirectional or zero-width characters. | A test fails if any tracked text file holds such a character. | `tests/test_no_hidden_characters.py` |
| T17 | A dependency is compromised or vulnerable. | Two runtime dependencies (PyYAML, `cryptography`), each with a written reason; the release checks include `pip-audit` and `bandit`, reported in [security-review.md](security-review.md). | [architecture.md](architecture.md) (Dependencies); [security-review.md](security-review.md) |

## Residual risks and non-goals

These are known and accepted; the README's Limitations section is the user-facing list.

- **The policy is a guard rail, not access control.** It cannot know whether you are authorised to
  scan a private network. A user with the source can change it. It protects against mistakes and
  against surprising inputs, not against an operator who means to misuse the tool.
- **Authorisation is the operator's responsibility.** Private ranges are allowed by default
  because home labs live there. Scanning someone else's private network without permission is
  still unauthorised.
- **DNS is trusted to the extent of the policy.** A hostile resolver cannot make the tool reach a
  refused range, but it can point a name at a different allowed address (for example another
  machine on the same private network).
- **Hostile services can lie.** A banner, an HTTP `Server` header or a certificate is what the
  service chose to say. Service names and findings are evidence of a weak kind, and the report says
  how confident it is.
- **Reports are plain text.** They are not encrypted or signed, and they list what is open on your
  network. Treat a report and a baseline like any other inventory of your systems.
- **No protection from a compromised host.** If the machine running the tool is compromised, so
  are its reports and baselines.
- **The scanner is visible.** It does not try to hide, slow itself to evade detection or spoof
  anything. An intrusion detection system will see the scan, as it should.
- **Not verified here:** behaviour against real dropped packets, a real DNS server and a real
  console Ctrl+C; the exact timing on Linux. See [architecture.md](architecture.md) and the README.
