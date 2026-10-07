# Port specifications and presets

Implemented in `src/network_scanner/ports/`. The scan command that will use them does not
exist yet.

## Specification grammar

A comma-separated list with no spaces. Each item is one of:

- a port, `1`-`65535`, decimal, no leading zeros (`080` is refused as ambiguous);
- a range `low-high`, both ports, `low <= high`;
- a preset name, lower case (currently only `common`).

The result is sorted and has no duplicates. The number of distinct ports is computed by
merging intervals before anything is expanded, and it must not exceed the per-target cap
(1024 by default, never more than 65535). A specification is at most 4096 characters.
Non-ASCII characters, spaces and control characters are refused.

Tests: `tests/test_ports_spec.py`.

## The `common` preset

A hand-curated list of well-known TCP service ports. It is **curated, not ranked**: it
says nothing about which ports are most often open, and it is not a complete list of
interesting ports. Service names are conventional labels, not authoritative registry data.
The data lives in `src/network_scanner/ports/data/ports_common.yaml`, is loaded with
`yaml.safe_load` only (after a check that refuses anchors, aliases, explicit tags,
duplicate keys and deep nesting), and is validated against a closed schema.

The table below is generated from that file, and `tests/test_docs_drift.py` fails if the
two differ.

<!-- BEGIN GENERATED: ports_common -->
| Port | Service |
|------|---------|
| 21 | ftp |
| 22 | ssh |
| 23 | telnet |
| 25 | smtp |
| 53 | dns |
| 80 | http |
| 110 | pop3 |
| 111 | rpcbind |
| 135 | msrpc |
| 139 | netbios-ssn |
| 143 | imap |
| 389 | ldap |
| 443 | https |
| 445 | smb |
| 465 | smtps |
| 587 | submission |
| 631 | ipp |
| 636 | ldaps |
| 993 | imaps |
| 995 | pop3s |
| 1433 | mssql |
| 1521 | oracle |
| 1883 | mqtt |
| 2049 | nfs |
| 2375 | docker |
| 3306 | mysql |
| 3389 | rdp |
| 5432 | postgresql |
| 5900 | vnc |
| 5985 | winrm-http |
| 5986 | winrm-https |
| 6379 | redis |
| 8080 | http-alt |
| 8443 | https-alt |
| 8883 | mqtts |
| 9200 | elasticsearch |
| 11211 | memcached |
| 27017 | mongodb |
<!-- END GENERATED: ports_common -->

Tests: `tests/test_ports_presets.py`.
