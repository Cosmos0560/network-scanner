# Rule files

Two kinds of YAML rule files drive what the scanner reports about an open port:

- **fingerprint rules** turn what a service said (a banner, an HTTP answer, a TLS handshake) into a
  service name and a confidence;
- **finding rules** turn a service name and the TLS facts into findings that carry evidence.

Both are loaded by the same strict loader: a size cap, regular files only, UTF-8, the shared safe
YAML loader (no anchors, aliases, explicit tags, duplicate keys or deep nesting, then
`yaml.safe_load`), a closed schema, and a restricted regular-expression subset. How the loader
works and why is in [architecture.md](architecture.md) ("Rule files" and "Findings"); this page is
the reference for the files and the built-in rules.

**What a rule file can and cannot do today.** `network-scanner rules validate [--kind KIND] [PATH
...]` checks a file you wrote (see [cli.md](cli.md)). The `scan` and `baseline` commands use only
the rules built into the package; there is no option to load a rule file into a scan. Validation is
for people who write rules to contribute (see [../CONTRIBUTING.md](../CONTRIBUTING.md)).

Rule files describe and name things. They contain no vulnerability data, no product versions and no
ATT&CK mapping: an open port is not an observed technique.

## Fingerprint rule files

A file has exactly `schema_version: 1` and `rules`. A rule has exactly these keys:

| Key | Meaning |
|-----|---------|
| `id` | Unique within the file. Lower case letters, digits and `-`. |
| `service` | The service name reported, for example `ssh`. |
| `confidence` | `low`, `medium` or `high`: how strongly the evidence points at the service name. It is not a severity. |
| `description` | One sentence on what the rule looks at. |
| `match` | One or more conditions; the rule applies when all of them hold. |

Conditions in `match`: `banner_regex` (searched in the sanitised text the service sent unprompted),
`http_server_regex` (searched in the `Server` header of an HTTP answer), `http_response: true` (a
valid HTTP/1.0 or 1.1 status line came back) and `tls: true` (a TLS handshake completed). Among the
rules that apply, the highest confidence wins and a tie goes to the earlier rule.

Regular expressions use a small safe subset and only ever see the first characters of their input;
the limits are in the table in [architecture.md](architecture.md) and the reasoning, including what
this does not prove, is in the same place and in [performance.md](performance.md).

### Built-in fingerprint rules

<!-- BEGIN GENERATED: fingerprint_rules -->
| Rule | Service | Confidence | Matches when | Description |
|------|---------|------------|--------------|-------------|
| `ssh-identification` | ssh | high | banner matches `^SSH-[0-9]\.[0-9]+-` | SSH identification string, SSH-protoversion-softwareversion (RFC 4253 section 4.2). |
| `vnc-protocol-version` | vnc | high | banner matches `^RFB [0-9]{3}\.[0-9]{3}` | RFB ProtocolVersion message, RFB xxx.yyy (RFC 6143 section 7.1.1). |
| `http-status-line` | http | high | an HTTP status line was received | A valid HTTP/1.x status line in reply to a HEAD request. |
| `tls-handshake` | tls | high | a TLS handshake completed | A TLS handshake completed, so the port speaks TLS (the application protocol is not probed). |
| `ftp-greeting` | ftp | medium | banner matches `^220[ -].*[Ff][Tt][Pp]` | A 220 greeting that names FTP (RFC 959 section 4.2). |
| `smtp-greeting` | smtp | medium | banner matches `^220[ -].*SMTP` | A 220 greeting that names SMTP or ESMTP (RFC 5321 section 4.2). |
| `pop3-greeting` | pop3 | medium | banner matches `^\+OK` | A +OK greeting (RFC 1939 section 4). |
| `imap-greeting` | imap | medium | banner matches `^\* OK` | An untagged OK greeting (RFC 3501 section 7.1.1). |
| `telnet-login-prompt` | telnet | low | banner matches `[Ll]ogin:$` | The text ends with a login prompt. Weak evidence, since other services print one too. |
<!-- END GENERATED: fingerprint_rules -->

These nine rules are everything the scanner can name. A service that speaks another protocol, or
that waits for the client to speak and is neither HTTP nor TLS, is reported as open with no service.
An HTTPS port is named `tls`: the application protocol inside is not probed.

## Finding rule files

A file has the same envelope. A rule has exactly `id`, `title`, `severity`, `confidence`,
`description`, `evidence`, `when` and, optionally, `references`.

- `severity` is how much the finding would matter if it is right: `info`, `low`, `medium`, `high`
  or `critical`. `confidence` is how sure the evidence makes us: `low`, `medium`, `high`, or
  `from_service`, which takes the confidence of the fingerprint rule that named the service (so a
  telnet finding that rests on a low-confidence fingerprint stays low confidence). The two are
  separate fields on purpose.
- `when` has one or more conditions that must all hold: `service`, `tls_version_in`, and the flags
  `tls_expired`, `tls_hostname_mismatch`, `tls_self_issued` and `tls_unreadable` (each must be
  `true`).
- `evidence` is a template. `{name}` is replaced by one of the facts below; any other brace is
  refused when the file is loaded. The result is sanitised again and capped.
- `references` are CWE ids and RFC numbers, optionally with a section, and only where precise.

### Evidence fields

<!-- BEGIN GENERATED: evidence_fields -->
`{address}`, `{banner}`, `{http_server}`, `{port}`, `{service}`, `{service_confidence}`, `{service_rule}`, `{tls_cipher}`, `{tls_expired}`, `{tls_hostname_match}`, `{tls_issuer}`, `{tls_not_after}`, `{tls_not_before}`, `{tls_parse_error}`, `{tls_san}`, `{tls_self_issued}`, `{tls_self_signature_valid}`, `{tls_sha256}`, `{tls_subject}`, `{tls_version}`
<!-- END GENERATED: evidence_fields -->

### Built-in finding rules

<!-- BEGIN GENERATED: finding_rules -->
| Rule | Severity | Confidence | References | Fires when |
|------|----------|------------|------------|------------|
| `cleartext-telnet` | medium | from the service | CWE-319, RFC 854 | Telnet service (remote login without encryption) |
| `cleartext-ftp` | low | from the service | CWE-319, RFC 959 | FTP service (control connection not encrypted at connect) |
| `tls-deprecated-version` | medium | high | RFC 8996 | Deprecated TLS or SSL version negotiated |
| `tls-certificate-expired` | medium | high | RFC 5280 section 4.1.2.5 | Certificate has expired |
| `tls-certificate-hostname-mismatch` | medium | high | RFC 9525 | Certificate does not cover the requested name |
| `tls-certificate-self-issued` | info | high | RFC 5280 | Certificate is self-issued (issuer equals subject) |
| `tls-certificate-unreadable` | info | high | none | Certificate could not be read |
<!-- END GENERATED: finding_rules -->

Each rule has a positive and a negative test; `tests/test_findings.py` fails if one is missing.
What the rules cannot see:

- `tls-deprecated-version` judges only the TLS version actually negotiated. The scanner offers TLS
  1.2 or newer, so end to end it can only fire for a server that negotiates an older version
  despite that offer. It is tested on synthetic observations. A server that speaks nothing newer
  than TLS 1.1 fails the handshake and is reported without a certificate and without this finding.
  The scanner does not test whether a TLS 1.3 server also accepts older versions.
- `tls-certificate-self-issued` says issuer equals subject. It says nothing about trust: no chain is
  built and no trust store is consulted. The evidence also shows separately whether the signature
  verifies under the certificate's own key.
- `tls-certificate-hostname-mismatch` fires only when the target was given as a host name; an IP
  target has no requested name to compare.
- `cleartext-ftp` only says the greeting arrived without TLS. The scanner does not check whether
  the server offers an upgrade (`AUTH TLS`).

## Validating a file

```
network-scanner rules validate PATH [PATH ...]
network-scanner rules validate --kind findings PATH
network-scanner rules validate                 # the built-in fingerprint rules
network-scanner rules validate --kind findings # the built-in finding rules
```

Exit code 0 when every file is valid, 2 when any is invalid or unreadable. An error names the file,
the place in it (for example `rules[3].match.banner_regex`) and a stable error code.
