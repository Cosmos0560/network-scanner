# Architecture notes

This file records design decisions and the reason for every dependency. It grows with
the project; the full architecture description is added in a later phase. The approved
plan is [PLAN.md](../PLAN.md).

## Layers

Packages under `src/network_scanner` sit in numbered layers (`core` 0; `scope`, `ports`
1; `net`, `rules` 2; `engine` 3; `fingerprint`, `findings` 4; `baseline`, `output` 5;
`lab` 6; `cli` 7). `scripts/check_architecture.py` enforces, with the AST:

1. A module may import only from its own layer number or a lower one. Packages that
   share a layer number may therefore import each other; the layer table in the script
   is the single source of truth.
2. Only `net`, `lab` and `cli` may import `socket`, `ssl`, `time` or `random`, use the
   `asyncio` stream APIs, or call `datetime.now()`, `utcnow()` or `today()`. Decision
   logic receives clocks, sleepers, resolvers and connectors through the interfaces in
   `core/interfaces.py`.
3. Dynamic imports (`__import__`, `importlib.import_module`) are rejected, since they
   would bypass the two rules above.
4. A package that is not in the layer table is itself a violation, so a new package
   cannot be added without deciding its layer.
5. There are no import cycles, neither between modules (`import_cycle`) nor between
   packages (`package_cycle`; this is how a cycle between peer packages on one layer
   is caught). Imports inside functions and under `if TYPE_CHECKING` count. A module also
   depends on its parent packages, because importing it runs their `__init__` first, so a
   package `__init__` must not import its own submodules.
6. Only `net/connector.py` may use `open_connection`, `create_connection`, `sock_connect`
   or `connect_ex` (`connect_outside_connector`), so every connection to a target passes
   the policy re-check described below. This is a guard rail, not a proof: a bare
   `sock.connect()` is not matched by name, and the rule only covers `src/`.

The check also runs inside pytest, with tests that plant violations in a temporary tree.

## Dependencies

| Package | Kind | Reason |
|---------|------|--------|
| cryptography | runtime (declared in Phase 4; first imported by `net/certificate.py` and `lab/certs.py`) | Certificate parsing and the self-signature check (decisions D1 and D6); see below. Installing it also installs `cffi` and `pycparser` (its own dependencies; both were pulled in when it was added to the development environment on 2026-10-08). |
| PyYAML | runtime (declared in Phase 2; first imported by `ports/presets.py`) | The `common` port preset is YAML data and so will be the rules (decision D3). The stdlib has no YAML parser. Loaded with `yaml.safe_load` only; before loading, an event-stream check refuses anchors, aliases, explicit tags, duplicate keys and deep nesting (see `docs/ports.md`). `tests/test_ports_presets.py` fails if any source file calls an unsafe loader. |
| hatchling | build | Build backend for the src layout. Not installed at runtime. |
| pytest, pytest-cov | dev | Test runner and the coverage threshold in the gate. |
| ruff | dev | Lint and format. |
| mypy | dev | Strict type check on both platform settings. |
| types-PyYAML | dev | Type stubs, so mypy can stay strict. |

`pyproject.toml` declares a runtime dependency only in the phase whose code first imports
it: PyYAML since Phase 2, `cryptography` from Phase 4.

PyYAML wheels, checked 2026-10-07 the same way as below (`uv pip compile --only-binary
:all:`): PyYAML 6.0.3 and types-PyYAML resolve for Python 3.11, 3.12 and 3.13 on
`x86_64-pc-windows-msvc` and `x86_64-manylinux_2_39`.

### Why `cryptography` (decision D1)

With verification switched off, Python's `ssl` module returns the peer certificate only
as raw DER bytes, and the standard library has no public X.509 parser. The options were
a hand-written DER parser or a maintained library. A hand-written parser would be the
largest piece of untrusted-input parsing in the project. Certificates come from servers
we do not control, so we use `cryptography` (parsing in a widely reviewed library)
instead of writing our own.

It also lets us report two separate facts about a certificate (decision D6):
"self-issued" (issuer equals subject) and "signature verifies against its own key",
the latter using the library's signature verification.

### Wheel availability, checked 2026-10-07

Checked against PyPI for `cryptography` 50.0.2 (the latest release at that time):

- The release has `cp311-abi3` wheels for `win_amd64` and for `manylinux_2_28_x86_64`
  (and other manylinux and musllinux variants). A `cp311-abi3` wheel installs on
  CPython 3.11, 3.12 and 3.13.
- `uv pip compile --only-binary :all:` resolves `cryptography` for each of Python 3.11,
  3.12 and 3.13 on `x86_64-pc-windows-msvc` and `x86_64-manylinux_2_39` without needing
  a source build.

This shows that wheels exist for the platforms CI uses. It is not a test of importing
the package on every combination; CI does that now that the dependency is declared.

### How `cryptography` is used, and its version range

`pyproject.toml` declares `cryptography>=42,<51`. The lower bound is the first release that
has every call the code makes (`not_valid_after_utc`, `signature_algorithm_parameters`); the
upper bound is the next major release, which has not been looked at. Only the newest release
is installed by the tests and by CI, so the lower bound is a statement about the API, not a
tested configuration.

The library is used for exactly two jobs, both on untrusted bytes and both without trusting
anything: parsing a certificate (`x509.load_der_x509_certificate`) and verifying a
certificate's signature under its own public key (`public_key().verify`). It is never used
to build a chain, check a trust store or validate a certificate, and the reports say "self
issued" and "signature verifies under its own key" rather than "valid" or "trusted"
(`net/certificate.py`). The lab also uses it to generate its ephemeral certificates
(`lab/certs.py`). Hand-written DER parsing is not used anywhere.

## Other decisions

- D2: no committed key or certificate. The demo and the tests generate an ephemeral
  self-signed certificate at runtime into a temporary directory that is deleted
  afterwards.
- D4: `169.254.0.0/16` (including cloud metadata `169.254.169.254`) is always refused;
  `100.64.0.0/10` (CGNAT) is treated as public.
- D5: the port preset is a curated `common` list of well-known service ports,
  documented as curated, not frequency-ranked.
- No ATT&CK mapping in v1. An open port is not an observed technique. Findings carry
  evidence text and, only where precise, a CWE or RFC reference.

## Scope and ports (Phase 2)

Details are in [scope-policy.md](scope-policy.md) and [ports.md](ports.md). Design points
that are not obvious from the code:

- Address parsing and formatting are our own (`scope/parser.py`). `ipaddress` and
  `socket` are used only inside tests, as a cross-check: an exhaustive test over small
  alphabets compares our IPv4 acceptance with `inet_aton` and our IPv6 acceptance and
  formatting with `ipaddress`.
- Classification is a table of CIDR blocks with the most specific block winning, and a
  second lookup that reports which classes occur in an address range without iterating
  it. Both are in `scope/classify.py`; the table in the documentation is generated from it.
- `plan_targets` (in `scope/policy.py`) is the single entry point that turns target
  strings into the pinned scan list. It takes the resolver and the confirmation callback
  as arguments, so it needs no network and no terminal in tests.
- Reason codes live in `core/errors.py` with the other shared error types. Phase 2 added
  fifteen to the six the plan names.
- Fixed input bounds that are not per-run settings (answers per name, resolve timeout,
  scope-file size, port-spec length) are constants in `core/limits.py`, not fields of
  `Limits`, so the report schema is unchanged.
- Interpretations that go beyond the plan, all on the conservative side: IPv6 space that
  is not global unicast, unique-local, link-local, loopback or a listed special block is
  refused as `reserved`; `192.0.0.0/24`, `192.88.99.0/24` and `64:ff9b:1::/48` are refused;
  a name with more than eight answers is refused rather than truncated.

## Scanning (Phase 3)

How a `scan` run is put together, and what each part guarantees. Timing observations are in
[performance.md](performance.md) and nowhere else.

**Flow.** `cli/commands/scan.py` parses the arguments, builds `Limits`, parses the port
specification, loads the scope file, and plans the targets with `plan_targets` (Phase 2).
If the plan holds public addresses and a person can answer, the confirmation question is
asked between two separate `asyncio.run` calls (planning, then scanning), so that Ctrl+C at
the prompt is an ordinary `KeyboardInterrupt`. Then `engine/scan.py` runs the probes and the
renderers in `output/` print the report.

**No socket without the policy.** The connector (`net/connector.py`) re-checks every
connection against the same `ScopeOptions` the plan was made with: the address must be a
plain IP literal (a name, a CIDR or an odd form is refused, and nothing is resolved there),
the policy must allow it, and the port must be 1-65535. It then connects with
`AI_NUMERICHOST`, so no lookup can happen. A caller that skips the planner gets
`ScopeRefusal` and no socket. The architecture check keeps other modules from connecting.

**Port states.** `open`: the connection was established, and is closed again at once, with
nothing sent. `closed`: refused. `filtered`: no answer within the connect timeout, or the
network was unreachable. `error`: anything else, such as a reset while connecting. The
mapping from operating-system errors to our own `NetErrorCode` (`net/oserrors.py`) is
table-driven and covers the Windows error numbers that the Proactor loop reports without a
useful exception class; it is tested with synthetic exceptions on every platform.

**Bounds.** At most `concurrency` worker tasks exist whatever the number of probes: they
pull (target, port) pairs lazily from one shared iterator. Each probe has the connect
timeout, the run has the total timeout, the rate limiter (a token bucket on an injected
clock and sleeper, capacity one so starts are spaced) paces connection starts, and
targets x ports may not exceed 100,000 probes (`MAX_PROBES_PER_RUN`).

**Results and ending.** Results are sorted by (position of the target in the plan, port),
independent of completion order. Ctrl+C (cancellation) and the total timeout do not raise:
the workers are cancelled and awaited, and a partial report with `complete: false` is
returned together with the reason. Exit codes: 0 complete, 2 usage error or scope refusal,
3 runtime error or total timeout, 130 interrupted. Any other exception from a probe aborts
the run after the remaining workers have been cancelled.

**The lab.** `lab/servers.py` opens listening sockets ("open") and bound-but-not-listening
sockets ("closed") on loopback, on OS-assigned ports, and refuses any other host. A closed
port is held, not merely free, so it cannot become open by a race. Hostile servers
(accept then close, reset, silent) are test-only, in `tests/hostile.py`.

**How the tests stay deterministic.** `tests/virtual_loop.py` is an event loop whose clock
is a counter that jumps to the next timer, so engine, rate-limiter and timeout tests assert
exact virtual times and never sleep; a loop that would wait forever fails the test instead
of hanging. Tests that need real sockets use the lab or `tests/hostile.py`, bind loopback on
port 0, and wait until a server has handled every connection before closing it (closing
earlier abandons connections that are still being accepted, which showed up as leaked
transports). `filterwarnings = error` plus a garbage collection after each test makes
`ResourceWarning` and "coroutine was never awaited" fail the run, and
`tests/test_leak_detection.py` proves that with a deliberately leaking test file.

**Not verified.** Real dropped packets (`filtered` is tested with an injected connector),
real DNS (the system resolver adapter is exercised only through an injected lookup), a real
Ctrl+C in a console (tested in-process with `signal.raise_signal`, which exercises the
same `asyncio.run` interrupt path but not a terminal), and Linux timing.

## Fingerprinting and TLS (Phase 4)

What an open port says about itself is read by a small inspector, matched against rule files,
and turned into a service name. The pieces are built and tested end to end against the lab;
`scan` does not call the inspector yet (see "Known gaps").

**Hostile input.** Everything a service sends (banners, HTTP headers, certificates) is
treated as hostile. Every read is capped in bytes, lines and time by constants in
`core/limits.py` (table below), nothing is read until end of stream, and all text passes the
sanitiser (`core/sanitize.py`) before it is stored, matched or shown. A banner is cut at its
first line break, so a service that never sends one is stopped by the byte cap or by the
deadline, which covers the whole read, not each chunk, so a slow drip cannot keep a scan
waiting.

### What is sent

| Probe | What the scanner sends | Notes |
|-------|------------------------|-------|
| `banner` | nothing | Connects and listens. Services that speak first (SSH, FTP, SMTP, POP3, IMAP, VNC) are identified here and never sent anything. |
| `http_head` | one fixed request, shown below | No body, no credentials, no other method. Redirects are not followed. |
| `tls` | a TLS ClientHello (TLS 1.2 or newer) and the rest of the handshake | Nothing is sent after the handshake. The certificate is not verified (see "Certificates"). |

The HTTP request is built from this template. The only inputs are the host (the requested
host name, or the address literal, checked against a strict character set) and the tool
version (checked the same way):

```
HEAD / HTTP/1.1
Host: <host>:<port>
User-Agent: network-scanner/<version>
Accept: */*
Connection: close
```

(every line ends with CR LF, followed by one empty line). Nothing sent ever depends on what
the service said. No credentials are tried and no authentication is attempted.

### Which probe runs when

`engine/probe_plan.py` decides, as a pure function of the port, the probes already tried and
the limit `probes_per_open_port` (3 at most, since it is a ceiling). It always starts with
`banner`. If the service said anything, the plan ends. If it was silent, `http_head` and `tls`
are tried until one gets an answer, in an order that depends only on the port number: ports
that are normally TLS-wrapped from the first byte (`TLS_FIRST_PORTS`) try TLS first. A service
can run on any port, so both are tried on every port. Each probe is its own connection, made
through the policy-checking connector after the shared rate limiter, so the connection-rate
cap and the scope policy cover probes exactly as they cover the scan. The connect-scan
connection itself is separate and counts as the scan, not as a probe.

`engine/inspect.py` runs the plan. A failed, reset or timed-out probe is simply an unanswered
probe. `run_scan` takes an optional inspector: a worker that finds a port open records the
open result first, then inspects, so inspection counts against the same concurrency bound and
total timeout and an interrupted inspection never loses the open result.

### Bounds

<!-- BEGIN GENERATED: probe_limits -->
| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_BANNER_CHARS` | 256 | Sanitised banner text kept per port. |
| `HTTP_HEAD_TIMEOUT_S` | 5 | Deadline (seconds) for sending the HEAD request and reading the response head. |
| `MAX_HTTP_HEAD_BYTES` | 4096 | Bytes of the HTTP status line and headers that are read; the body never is. |
| `MAX_HTTP_HEADER_LINES` | 64 | Header lines looked at; the rest are ignored. |
| `MAX_HTTP_SERVER_CHARS` | 200 | Sanitised `Server` header kept. |
| `TLS_HANDSHAKE_TIMEOUT_S` | 5 | Deadline (seconds) for the TLS handshake, and separately for the connection under it. |
| `CLOSE_TIMEOUT_S` | 1 | A polite close waits this long (seconds), then the connection is aborted. |
| `ABORT_GRACE_S` | 0.1 | After an abort, how long (seconds) to wait for the transport to report closed. |
| `MAX_CERT_DER_BYTES` | 32768 | A larger certificate is not parsed at all. |
| `MAX_CERT_FIELD_CHARS` | 256 | Sanitised subject, issuer and each subjectAltName entry kept. |
| `MAX_SAN_ENTRIES` | 64 | subjectAltName entries listed. |
| `MAX_RULE_FILE_BYTES` | 65536 | A larger rule file is refused. |
| `MAX_RULES` | 256 | Rules per file. |
| `MAX_RULE_FILES` | 32 | Files accepted by one `rules validate` call. |
| `MAX_REGEX_PATTERN_CHARS` | 200 | Longest rule regular expression. |
| `MAX_REGEX_INPUT_CHARS` | 256 | A pattern only sees this many leading characters of its input. |
| `MAX_REGEX_REPEAT` | 255 | Largest count in `{m,n}`. |
| `MAX_REGEX_COST` | 100000 | Budget for a pattern's backtracking estimate (below). |
| `MAX_REGEX_GROUP_DEPTH` | 6 | Deepest nesting of groups in a pattern. |
| `MAX_EVIDENCE_CHARS` | 400 | Sanitised evidence text kept per finding. |
<!-- END GENERATED: probe_limits -->

The banner wait (`banner_timeout_s`), the banner byte cap (`banner_max_bytes`) and the probe
limit (`probes_per_open_port`) are per-run `Limits`; everything in the table is a fixed bound.
`tests/test_docs_drift.py` fails if this table and `core/limits.py` disagree.

### Certificates (decisions D1, D2 and D6)

`net/tls.py` upgrades a connection the connector opened and reads the peer's certificate.
Verification is switched off on purpose, because a scanner has to see whatever certificate a
service presents, including expired, self-signed and wrongly named ones. **Reading a
certificate is not validating it.** No chain is built, no trust store is consulted, and
nothing in the output says "valid" or "trusted". `net/certificate.py` reports facts:

- `self_issued`: issuer and subject name are equal.
- `self_signature_valid`: the signature verifies under the certificate's own public key,
  checked with the `cryptography` API. `null` means the check could not be made (a key type
  or algorithm the library cannot verify).
- The two are separate facts. A certificate can say it is self-issued with a signature that
  does not verify, and a certificate with different names can be signed by its own key; both
  cases are tested. A signature made by another kind of key (an EC authority signing an RSA
  certificate) simply does not verify under this one, which is `false`.
- `expired`: the injected clock is after notAfter. A certificate that is not valid yet is not
  called expired; `not_before` shows it.
- `hostname_match`: the requested name is covered by a subjectAltName entry. The subject
  common name is not consulted (RFC 9525), a wildcard is a whole left-most label with at least
  two labels after it, and an IP address matches only an IP entry. It is `null` when no name
  was requested, which is always the case for an IP target.
- `san` lists `DNS:` and `IP:` entries only, at most the table's cap, with `san_truncated` set
  when there were more. Every text field is sanitised and capped.

The certificate is parsed by `cryptography` after a size check; a larger certificate is not
parsed (its SHA-256 is still reported). Any failure becomes a fixed `parse_error` code
(`no_certificate`, `certificate_too_large`, `malformed_certificate`) and the handshake still
counts as TLS. Tests build every certificate at runtime (`lab/certs.py`), including the
shapes above, an oversized one, every truncation of a real one and seeded random corruption;
no key or certificate is committed, and `tests/test_no_committed_keys.py` fails if one is
ever tracked by git.

### Rule files (decision D3)

`rules/` loads and validates YAML rule files; `network-scanner rules validate [PATH ...]`
checks them (no path: the built-in rules in `rules/data/fingerprints.yaml`).

- Loading: size cap, regular files only, UTF-8, then `core/yamlsafe.py` (the loader shared with
  the port presets: no aliases, anchors, explicit tags, duplicate keys or deep nesting, then
  `yaml.safe_load`), then a closed schema.
- Schema: the file has exactly `schema_version: 1` and `rules`. A rule has exactly `id`,
  `service`, `confidence` (`low`, `medium`, `high`), `description` and `match`. `match` has one
  or more of `banner_regex`, `http_server_regex`, `http_response: true` and `tls: true`, and a
  rule applies when all of them hold. Unknown keys, missing keys, wrong types, empty `match`,
  and duplicate ids are refused, each with a stable error code and the location (for example
  `rules[3].match.banner_regex: unsafe_regex`).
- Matching (`fingerprint/match.py`): among the rules that apply, the highest confidence wins and
  a tie goes to the earlier rule. Confidence is how strongly the evidence points at the service
  name; it is not a severity.
- Regular expressions are limited to a safe subset (`rules/regex_safety.py`): no
  backreferences, lookaround, inline flags, named groups or possessive forms; a repeated group
  may not contain a quantifier or an alternation; every choice multiplies a cost estimate
  that must stay within a budget (`*` and `+` count as the input length, `?` as 2, `{m,n}` as
  n-m+1, an alternation as its number of branches), which is what stops `.*.*.*x`, `a?a?a?...`
  and `(a|a)(a|a)...`; printable ASCII only; a length cap; and a pattern is only ever run on
  the first characters of its input (table above). **This is a structural filter, not a proof
  of linear time.** The estimate over-counts on purpose, so it rejects some harmless patterns,
  and a pattern it accepts can still be slow in the polynomial sense; the budget and the input
  cap bound how slow (see [performance.md](performance.md)).
- Built-in rules identify ssh, vnc, http and tls with high confidence, ftp, smtp, pop3 and imap
  from their greetings with medium, and telnet from a login prompt with low (many services print
  one). They name protocols, not products or versions, and carry no vulnerability data.

### The lab

`lab/services.py` runs four loopback services with known fingerprints: an SSH-like and a
telnet-like service (a banner, then close), an HTTP service (`HEAD` and `GET` get a fixed
`Server` header, anything else gets 400) and a TLS service. They speak just enough to be
recognised. The TLS service takes its certificate from `lab/certs.py`; the key is written to a
temporary directory only while the TLS library loads it, and the directory is deleted at once
(a test checks this). Hostile servers (endless and dripping banners, TLS garbage, alerts,
handshakes that never finish, escape sequences in banners) are test-only, in `tests/hostile.py`.

### Known gaps

- `scan` does not run the inspector, so its report has no services yet. The report schema
  has no place for observations; wiring them in belongs with the baseline work.
- An HTTPS service is identified as TLS. The HTTP `Server` header is read only over plain
  HTTP, and the certificate of the leaf only (no chain is read).
- Only TLS 1.2 and newer are offered. A server that speaks nothing newer fails the handshake
  and is not reported as a finding (PLAN.md risk R3).
- The `cryptography` lower bound is a statement about the API used, not a tested
  configuration; only the newest release is installed by the tests and CI.
- Tests ran on Windows with Python 3.13 on the day of writing. Linux and Python 3.11 and 3.12
  are covered by CI only after the maintainer pushes, and are not claimed here.
