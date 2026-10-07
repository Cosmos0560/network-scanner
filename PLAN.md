# network-scanner v1.0 plan (Step 0, awaiting approval)

Status: PROPOSED. No code is written until Otabek approves this file.
Section 0 lists the decisions that need an explicit yes or no.

## 0. Decisions that need approval

| # | Decision | Recommendation | Alternative |
|---|----------|----------------|-------------|
| D1 | How to read certificate fields. With verification off, Python's `ssl` returns only raw DER bytes, and the stdlib has no public X.509 parser. | Small strict DER reader of our own (subject, issuer, validity, SAN, SHA-256 of DER). Input capped at 64 KB, any parse failure becomes a `tls_parse_error` field, fuzz-style adversarial tests. Zero dependencies. | `cryptography` as a runtime dependency: more accurate, but a large binary wheel for one feature. |
| D2 | TLS test certificates. | Commit one test-only key and a few certificates inside the package (`lab/certs/`), marked "PUBLIC TEST KEY, NOT A SECRET". Reason: `demo` must start a TLS server on a fresh clone with no dev tools installed, so a dev-only generator cannot serve it. | Dev-only dependency that generates certs at test time; then `demo` needs the dev extras or loses its TLS server. |
| D3 | Rules format. | YAML via PyYAML (`safe_load` only). This is the only runtime dependency. | TOML via stdlib `tomllib`: zero runtime deps, but the brief says YAML. |
| D4 | Addresses the brief does not name. | 169.254.0.0/16 (IPv4 link-local, includes cloud metadata 169.254.169.254): always refused. 100.64.0.0/10 (CGNAT): treated as public, so it needs the full three-part gate. | Allow IPv4 link-local by default. |
| D5 | "Top ports" preset. | Ship a curated `common` preset of well-known service ports and document it as curated, NOT frequency-ranked. I have no measured frequency data I can truthfully cite, and nmap's list has its own licence. | Drop the preset name "top" entirely (same thing, different label). |
| D6 | Self-signed detection. | Report "self-issued" (issuer equals subject). Without a crypto library the signature is not verified, and the docs say so. | Follows D1: with `cryptography` the signature can be checked. |

## 1. Architecture

```
                         +---------------------------+
                         |            cli            |  argparse, exit codes, prompts
                         +-------------+-------------+
                                       |
              +------------------------+------------------------+
              |                        |                        |
        +-----v-----+            +-----v-----+            +-----v-----+
        |    lab    |            |  output   |            | baseline  |
        | mock lab  |            | table json|            | save/diff |
        | (loopback)|            | jsonl csv |            +-----+-----+
        +-----+-----+            +-----+-----+                  |
              |                        |                        |
              |                  +-----v------------------------v-----+
              |                  |      findings      fingerprint     |  pure decisions
              |                  +-----------------+------------------+
              |                                    |
              |                              +-----v-----+
              |                              |  engine   |  orchestration, uses ports
              |                              +--+-----+--+  (interfaces) only
              |                                 |     |
              |                     +-----------v+   +v-----------+
              +--------------------->    net     |   |   rules    |  YAML load + validate
                                    | sockets,   |   +-----+------+
                                    | ssl, DNS   |         |
                                    +-----+------+         |
                                          |                |
                                  +-------v------+  +------v------+
                                  |    scope     |  |    ports    |  pure parsers + policy
                                  +-------+------+  +------+------+
                                          |                |
                                  +-------v----------------v------+
                                  | core: model, errors, sanitize,|
                                  |       limits, interfaces      |
                                  +-------------------------------+
```

Imports go downward only. `check_architecture.py` enforces two things:

1. Layer order: a module may import only from its own layer or a lower one.
2. I/O quarantine: only `net`, `lab` and `cli` may import `socket`, `ssl`, `asyncio`
   stream APIs, `time`, `random`, `datetime.now`-style clocks. `engine` receives
   connector, resolver, clock and sleeper through interfaces defined in `core`.

## 2. Modules

| Layer | Package | Contents |
|-------|---------|----------|
| 0 | `core` | `model.py` (frozen dataclasses, enums), `errors.py`, `sanitize.py`, `limits.py` (defaults and ceilings), `interfaces.py` (Protocols: Clock, Sleeper, Resolver, Connector, TlsProber) |
| 1 | `scope` | `parser.py` (closed target grammar), `classify.py` (address classes), `policy.py` (pure decision), `scopefile.py` |
| 1 | `ports` | `spec.py` (lists, ranges), `presets.py` + `data/ports_common.yaml` |
| 2 | `net` | `connector.py`, `resolver.py`, `tls.py`, `oserrors.py` (errno and WinError to enum), `ratelimit.py` (token bucket, injected clock), `der.py` (D1) |
| 2 | `rules` | `loader.py`, `schema.py` (unknown fields, duplicate ids), `regex_safety.py`, `data/fingerprints.yaml`, `data/findings.yaml` |
| 3 | `engine` | `scan.py` (bounded concurrency, timeouts, cancellation, ordering), `probe_plan.py` |
| 4 | `fingerprint` | `match.py` (observation + rules to service) |
| 4 | `findings` | `evaluate.py` (services + TLS info + rules to findings) |
| 5 | `baseline` | `store.py` (versioned JSON), `diff.py` |
| 5 | `output` | `table.py`, `json_out.py`, `jsonl.py`, `csv_out.py` |
| 6 | `lab` | `servers.py` (ssh-like, http, tls, telnet-like), `certs/`. Hostile servers are test-only and live in `tests/`, not in the package |
| 7 | `cli` | `main.py`, `commands/` (scan, baseline, rules, demo) |

## 3. Data model (all frozen dataclasses, JSON-serialisable)

- `TargetSpec(raw, kind)` kind: ip, cidr, range, hostname
- `ResolvedTarget(display_name, address, family, origin_spec)`
- `ScopeDecision(allowed, address_class, reason_code)`
- `PortResult(address, port, state, error_code)` state: open, closed, filtered, error
- `Observation(banner, banner_truncated, probe, http_status, http_server, tls)`
- `TlsInfo(version, cipher, subject, issuer, not_before, not_after, san, sha256, self_issued, expired, hostname_match, parse_error)`
- `Service(name, rule_id, confidence)`
- `Finding(id, title, severity, confidence, address, port, evidence, references)`
- `ScanReport(schema_version, tool_version, started_at, complete, limits, targets, results, findings)`
- `Baseline(schema_version, created_at, entries)` keyed by (address, port)
- `Drift(new, closed, changed)`

Rules: text from the network is sanitised when captured and again when rendered.
No round-trip time or duration field in v1.0 (it is non-deterministic and would invite
speed claims). `started_at` comes from the injected clock and is ignored by `diff`.

Exit codes: 0 clean, 1 drift found or findings at or above `--fail-on`, 2 usage error
or scope refusal, 3 runtime error, 130 interrupted (partial report, `complete: false`).

## 4. Scope-policy spec

### 4.1 Target grammar (closed: anything not listed is refused)

| Form | Accepted | Refused examples |
|------|----------|------------------|
| IPv4 | exactly four decimal octets 0-255, no leading zeros | `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`, `010.0.0.1` |
| IPv6 | standard text form; zone id only on fe80::/10, `[A-Za-z0-9_.-]{1,16}` | `::ffff:10.0.0.1`, `::10.0.0.1`, zone id on other ranges |
| CIDR | `addr/prefix`, host bits must be zero | `192.168.1.5/24`, `10.0.0.0/33`, `10.0.0.0/-1` |
| Range | `a.b.c.d-e.f.g.h` or `a.b.c.d-N` (last octet), IPv4 only, start <= end | reversed ranges, cross-family, IPv6 ranges |
| Hostname | ASCII LDH labels 1-63 chars, total <= 253, last label not all digits | `1.2.3`, non-ASCII (use punycode), underscores, trailing dot, empty labels |

Input caps: one target string <= 255 chars; no NUL or control characters; target count is
computed arithmetically BEFORE expansion (a /8 is rejected without being materialised).
For CIDRs of /30 and shorter (IPv4) the network and broadcast addresses are skipped.

### 4.2 Address classes, checked in this order

1. ALWAYS REFUSED (no flag overrides): 0.0.0.0/8, `::`, multicast (224.0.0.0/4, ff00::/8),
   255.255.255.255, 240.0.0.0/4, 169.254.0.0/16 (D4), documentation and benchmark ranges
   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, 2001:db8::/32),
   IPv6 forms that embed IPv4: IPv4-mapped, IPv4-compatible, NAT64 64:ff9b::/96,
   6to4 2002::/16, Teredo 2001::/32. They are never unwrapped.
2. ALLOWED BY DEFAULT: 127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
   fc00::/7, fe80::/10.
3. PUBLIC (everything else, including 100.64.0.0/10): allowed only if ALL hold:
   `--allow-public` is given, the address is inside a scope-file entry, and the run is
   confirmed (`--yes`, or an interactive prompt on a TTY; non-TTY without `--yes` refuses).

### 4.3 Scope file

Plain UTF-8 text, one IP or CIDR literal per line, `#` comments. No hostnames. Public
entries no wider than /24 (IPv4) or /120 (IPv6). Size cap 64 KB. Parsed by the same
closed parser.

### 4.4 Hostnames

Resolved once through the injected resolver, with a timeout, at most 8 answers. Every
answer is classified. If ANY answer is refused or is public without full authorisation,
the whole hostname is refused (no partial scan). Connections go to the pinned IP literal.
The name is used only for display, SNI and hostname-mismatch checks. No re-resolution,
no redirects followed.

### 4.5 Fail closed

All targets are parsed, resolved and decided before the first connection. One refused
target aborts the run with exit code 2 and a stable reason code (for example
`ambiguous_numeric`, `embedded_ipv4`, `public_not_allowed`, `not_in_scope_file`,
`mixed_dns_answers`, `too_many_targets`).

### 4.6 Caps (proposal)

| Limit | Default | Ceiling (constant, not overridable) |
|-------|---------|-------------------------------------|
| Targets per run | 256 | 4096 |
| Ports per target | 1024 | 65535 |
| Concurrency | 64 | 512 |
| Connections per second | 100 | 1000 |
| Connect timeout | 3 s (see R2) | 30 s |
| Banner read | 2 s, 1024 bytes | 10 s, 4096 bytes |
| Total run timeout | 300 s | 3600 s |
| Connections per open port (probes) | 3 | 3 |

## 5. Phases (each about one 1.5 h session)

### Phase 1: scaffold, CI, core
Build: pyproject (src layout, console script), `.gitignore` (incl. graphify-out/),
LICENSE, README stub with the legal notice, `scripts/gate.py`,
`scripts/check_architecture.py`, `.github/workflows/ci.yml`, `core` (model, errors,
sanitize, limits, interfaces), `network-scanner --version`.
Accept: gate green locally; architecture test fails on a planted violation and on a
planted `import socket` in a pure layer; sanitiser tests cover ANSI, CR/LF, bidi, NUL,
invalid UTF-8; Otabek pushes and reports CI on all six jobs.

### Phase 2: targets, scope policy, ports
Build: `scope` (parser, classify, policy, scope file), fake resolver, confirmation
logic, `ports` (spec, `common` preset data), caps.
Accept: every bypass in section 4 is refused with its reason code; mixed private/public
DNS answers refuse the hostname; CIDR overflow and huge lists are rejected without
materialising; preset file has a drift test against its documented table.

### Phase 3: engine, net adapters, plain mock lab, `scan`
Build: connector, OS-error normalisation, rate limiter, engine (concurrency, timeouts,
cancellation, ordering), lab plain-TCP servers, `scan` with table and JSON output.
Accept: end-to-end scan of the lab returns exact expected states on Linux and Windows;
closed is tested against a bound-but-not-listening socket (no port race); rate limiter
and timeouts are tested with a fake clock; cancellation yields a partial report and
exit 130; hostile servers (accept-then-close, RST) do not crash or hang the run.

### Phase 4: fingerprinting, TLS, fingerprint rules
Build: banner read with caps, HTTP HEAD probe, TLS probe and certificate reader (D1),
lab HTTP and TLS servers, committed test certs (D2) with a regeneration note,
`rules` loader and validator, `rules validate`.
Accept: exact fingerprints for the four lab services; certificate fields match the
committed certs exactly (valid, expired, mismatched name, CA-issued leaf); endless
banner, slow drip, TLS garbage and truncated DER stay inside the caps; rule files with
unknown fields, duplicate ids or unsafe regex are rejected with specific errors.
This is the tightest phase. If it overruns, it stops at a commit boundary; tests are
not cut.

### Phase 5: findings, baseline and drift, remaining outputs, `demo`
Build: finding rules and evaluator, baseline save and diff with exit codes, JSONL and
CSV, `demo`.
Accept: each finding rule has a positive and a negative test and carries evidence;
diff reports new, closed and changed with the documented exit codes; CSV cells cannot
start a formula; output-injection suite passes for all four formats; `demo` runs on a
machine with no network.

### Phase 6: docs and final gate
Build: README (badges, pitch, ASCII architecture, quick start, real demo output, safety
claims with links, limitations, roadmap), docs/architecture.md, threat-model.md,
rules.md (generated table with drift test), performance.md, CONTRIBUTING, SECURITY
(GitHub private vulnerability reporting), CHANGELOG.
Accept: fresh-clone test passes; claim -> evidence table complete; pip-audit and bandit
run in a temporary venv outside the repo and results reported as they are; list of what
was NOT verified.

## 6. Dependencies

| Package | Kind | Reason |
|---------|------|--------|
| PyYAML | runtime | Rules are YAML data (D3); the stdlib has no YAML parser. `safe_load` only. |
| hatchling | build | Build backend for the src layout; not installed at runtime. |
| pytest | dev | Test runner. |
| pytest-cov | dev | Coverage threshold in the gate. |
| ruff | dev | Lint and format. |
| mypy | dev | Type check on both platforms. |
| types-PyYAML | dev | Stubs so mypy can stay strict. |
| pip-audit, bandit | final gate only | Temporary venv outside the repo, then deleted. Not in pyproject. |

Deliberately not used: pytest-asyncio (tests call `asyncio.run` through a small helper),
`cryptography` (unless D1 goes the other way), any CLI framework (argparse), any table
library, any HTTP library.

## 7. Risks

- R1 Certificate parsing without a crypto library (D1). A hand-written DER reader is the
  largest piece of untrusted-input parsing in the project. Mitigation: strict subset,
  size cap, parse errors become data, adversarial tests. Self-signed is reported as
  self-issued only (D6).
- R2 Windows may take about 2 s to report a refused connection, because it retries the
  SYN after a reset. With a short timeout a closed port would be misreported as
  filtered. To be MEASURED in Phase 3, not assumed; the default connect timeout (3 s
  proposed) is set from that measurement and documented.
- R3 TLS older than 1.2. Many current OpenSSL builds will not negotiate TLS 1.0 or 1.1
  at all. The finding is based on the negotiated version only; where the local OpenSSL
  refuses, the result is a handshake error, not a finding. The rule is unit-tested on a
  synthetic observation; an end-to-end test exists only if CI's OpenSSL allows it. This
  goes into README limitations. v1.0 also does not test whether a TLS 1.3 server ALSO
  accepts old versions.
- R4 Regex safety. `re` has no timeout. The validator is a conservative structural check
  (no backreferences, no lookaround, no quantified group containing a quantifier or
  alternation, length cap) plus a 4096-byte input cap. It is not a proof of linear
  time, and the docs will say that.
- R5 "Filtered" cannot be produced on loopback without firewall rules. It is tested
  through an injected connector that never completes. Not verified against real dropped
  packets; listed under "not verified".
- R6 Committed test key (D2) may be flagged by secret scanners or bandit. Mitigation:
  clear marking in the file, the directory README and SECURITY.md. The valid cert uses a
  far-future expiry; the expiry check takes the injected clock, so tests do not rot.
- R7 Windows Proactor loop: no `add_signal_handler`, different exceptions on reset.
  Ctrl+C is handled around the runner and tested by injected cancellation, not real
  signals. Real Ctrl+C on both OSes is a manual check for Otabek.
- R8 IPv6 loopback may be missing on a CI runner. IPv6 end-to-end tests would then be
  skipped with a visible reason, and the report says so instead of counting them green.
- R9 File-descriptor limits on Linux (often 1024) versus the concurrency ceiling of 512
  with up to 3 probe connections: probes share the same semaphore as connects.
- R10 The preset is curated, not ranked (D5). Named and documented accordingly.
- R11 ATT&CK references cannot be checked online (network is PyPI only). Proposal: at
  most T1021.001 (RDP) and T1021.002 (SMB/Windows Admin Shares), and only after Otabek
  confirms them on attack.mitre.org. Everything else ships without a mapping.
- R12 Demo output contains ephemeral port numbers, so it differs per run. The README
  shows one real run and says the ports vary.
- R13 Session size: Phase 4 is the most likely to overrun (see Phase 4 note).

## 8. Out of scope for v1.0 (README roadmap only)

UDP scanning, raw SYN or stealth scanning, OS fingerprinting, vulnerability or CVE
matching, credential testing, web crawling, distributed scanning, GUI.
