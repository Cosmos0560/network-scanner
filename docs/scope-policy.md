# Scope policy

How targets are parsed, classified and approved. Implemented in
`src/network_scanner/scope/`. Nothing here opens a connection: a plan is complete, and
every target decided, before the first connection of a run can be made. The commands that
use it are described in [cli.md](cli.md).

The tool is defensive. Scan only networks you own or have written permission to scan;
unauthorized scanning can be illegal.

## Target grammar

The grammar is closed: anything not listed is refused. It is parsed by our own code
(`scope/parser.py`), not by `ipaddress` or `socket`, whose accepted forms differ between
Python versions and platforms.

| Form | Accepted | Refused, for example |
|------|----------|----------------------|
| IPv4 | exactly four decimal octets 0-255, no leading zeros | `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`, `010.0.0.1` |
| IPv6 | standard text form, `::` at most once, optional dotted-quad tail; a zone id (`%name`, 1-16 of `A-Za-z0-9_.-`) only on `fe80::/10` and never percent-decoded | `[::1]`, `1::2::3`, a zone on any other range |
| CIDR | `address/prefix`, host bits zero | `192.168.1.5/24`, `10.0.0.0/33`, `10.0.0.0/-1` |
| Range | `a.b.c.d-e.f.g.h` or `a.b.c.d-N`, IPv4 only, start <= end | reversed ranges, IPv6 ranges |
| Hostname | ASCII letters, digits and `-`; labels 1-63 characters; at most 253 in total | non-ASCII (use punycode), underscores, a trailing dot, empty labels |

Numeric look-alikes are refused as `ambiguous_numeric`, not accepted as hostnames: a name
whose labels are all numbers in any form `inet_aton` reads (decimal, octal, hex), a name
whose last label is all digits, and non-ASCII digits or dots that normalise to an address
(fullwidth digits, ideographic full stops). A target is at most 255 characters and may not
contain whitespace or control, format or unassigned characters.

Counting is arithmetic. A CIDR of `/30` or shorter on IPv4 skips the network and broadcast
addresses; ranges and IPv6 blocks count every address. The total is checked against the
per-run cap (256 by default, never more than 4096) as each target is read, so a `/8`, an
IPv6 `/8` or a million-entry list is refused without being expanded.

Tests: `tests/test_scope_parser.py`, `tests/test_scope_policy.py`.

## Address classes

The class of an address is that of the most specific block below that contains it.

<!-- BEGIN GENERATED: scope_classes -->
| Block | Class | Policy | Note |
|-------|-------|--------|------|
| `0.0.0.0/0` | `public` | public: needs --allow-public, a scope-file entry and confirmation | everything not listed below, including 100.64.0.0/10 (CGNAT, decision D4) |
| `0.0.0.0/8` | `unspecified` | always refused | this network |
| `10.0.0.0/8` | `private` | allowed by default | RFC 1918 |
| `127.0.0.0/8` | `loopback` | allowed by default | loopback |
| `169.254.0.0/16` | `link_local_v4` | always refused | includes cloud metadata 169.254.169.254 (decision D4) |
| `172.16.0.0/12` | `private` | allowed by default | RFC 1918 |
| `192.0.0.0/24` | `reserved` | always refused | IETF protocol assignments |
| `192.0.2.0/24` | `documentation` | always refused | TEST-NET-1 |
| `192.88.99.0/24` | `reserved` | always refused | deprecated 6to4 relay anycast |
| `192.168.0.0/16` | `private` | allowed by default | RFC 1918 |
| `198.18.0.0/15` | `benchmark` | always refused | benchmarking |
| `198.51.100.0/24` | `documentation` | always refused | TEST-NET-2 |
| `203.0.113.0/24` | `documentation` | always refused | TEST-NET-3 |
| `224.0.0.0/4` | `multicast` | always refused | multicast |
| `240.0.0.0/4` | `reserved` | always refused | reserved (former class E) |
| `255.255.255.255/32` | `broadcast` | always refused | limited broadcast |
| `::/0` | `reserved` | always refused | everything not listed below: unallocated or special-purpose space |
| `::/96` | `embedded_ipv4` | always refused | IPv4-compatible (deprecated) |
| `::/128` | `unspecified` | always refused | unspecified address |
| `::1/128` | `loopback` | allowed by default | loopback |
| `::ffff:0:0/96` | `embedded_ipv4` | always refused | IPv4-mapped |
| `::ffff:0:0:0/96` | `embedded_ipv4` | always refused | IPv4-translated |
| `64:ff9b::/96` | `embedded_ipv4` | always refused | NAT64 |
| `64:ff9b:1::/48` | `embedded_ipv4` | always refused | local-use NAT64 |
| `2000::/3` | `public` | public: needs --allow-public, a scope-file entry and confirmation | global unicast |
| `2001::/23` | `reserved` | always refused | IETF protocol assignments |
| `2001::/32` | `embedded_ipv4` | always refused | Teredo |
| `2001:2::/48` | `benchmark` | always refused | benchmarking |
| `2001:db8::/32` | `documentation` | always refused | documentation |
| `2002::/16` | `embedded_ipv4` | always refused | 6to4 |
| `3fff::/20` | `documentation` | always refused | documentation |
| `fc00::/7` | `unique_local` | allowed by default | unique local addresses |
| `fe80::/10` | `link_local_v6` | allowed by default | link-local; the only range that takes a zone id |
| `ff00::/8` | `multicast` | always refused | multicast |
<!-- END GENERATED: scope_classes -->

Two choices go beyond the named ranges and are deliberately conservative: IPv6 space that
is not global unicast, unique-local, link-local, loopback or one of the listed special
blocks is refused as `reserved`, and a few IPv4 special-purpose blocks that are not
globally reachable (`192.0.0.0/24`, `192.88.99.0/24`) are refused as `reserved`.
`100.64.0.0/10` (CGNAT) is public (decision D4). Addresses embedding an IPv4 address are
never unwrapped.

Tests: `tests/test_scope_classify.py`.

## Decisions

1. Always refused, nothing overrides it: the classes marked "always refused" above.
2. Allowed by default: loopback, RFC 1918, IPv6 unique-local and IPv6 link-local.
3. Public: allowed only with **all** of `--allow-public`, an entry in the scope file, and
   confirmation (`--yes`, or an interactive prompt on a terminal; without a terminal and
   without `--yes` the run is refused).

Hostnames are resolved once through the injected resolver (5 s timeout, at most 8
answers). Every answer must be a plain IP address and is decided on its own. If any answer
is refused, or is public without full authorisation, the whole hostname is refused; there
is no partial scan. Answers are deduplicated and sorted, and the scan connects to the
pinned addresses, never the name. One name is resolved at most once per run.

All targets are validated before anything else happens, in this order: grammar and count
for every target in input order, then every literal address, then the hostnames, then
confirmation. The first problem aborts the run (exit code 2).

Tests: `tests/test_scope_policy.py`.

## Scope file

Plain UTF-8 text, at most 64 KB and 4096 entries, one IP or CIDR per line, `#` starts a
comment. No hostnames, ranges or zone ids. A public entry is at most `/24` (IPv4) or `/120`
(IPv6) wide. An entry may not cover any always-refused address. Control and format
characters are refused everywhere in the file, comments included.

Tests: `tests/test_scope_scopefile.py`.

## Reason codes

Every refusal carries one of these stable codes.

| Code | Meaning |
|------|---------|
| `ambiguous_numeric` | A numeric form with more than one reading (decimal, hex, octal, short, leading zeros, non-ASCII digits) |
| `embedded_ipv4` | An IPv6 address that embeds an IPv4 address (mapped, compatible, translated, NAT64, 6to4, Teredo) |
| `public_not_allowed` | A public address without `--allow-public` |
| `not_in_scope_file` | A public address that is not inside a scope-file entry |
| `mixed_dns_answers` | A hostname with at least one answer refused or not fully authorised, and at least one answer that would pass |
| `too_many_targets` | More targets than the per-run cap |
| `invalid_target` | Not an IP address, CIDR, range or hostname |
| `invalid_characters` | Whitespace, control, format or unassigned characters |
| `target_too_long` | A target string longer than 255 characters |
| `invalid_zone_id` | A zone id on a range other than `fe80::/10`, or with a bad form |
| `invalid_cidr` | A bad prefix, or a prefix on something that is not an IP address |
| `cidr_host_bits` | A CIDR with host bits set |
| `invalid_range` | A reversed, malformed or IPv6 range |
| `invalid_hostname` | A hostname that breaks the label rules, or non-ASCII |
| `always_refused` | An address in an always-refused class |
| `no_targets` | The target list is empty |
| `dns_failure` | The name did not resolve, timed out, or has no addresses |
| `too_many_dns_answers` | More than 8 answers |
| `invalid_dns_answer` | An answer that is not a plain IP address |
| `confirmation_required` | Public targets, no `--yes` and no terminal |
| `confirmation_declined` | The user answered no |

## Not verified

- Behaviour against a real DNS server or a real prompt: the resolver and the prompt are
  injected, and every test uses a fake.
- Whether the classification table matches every future change to the IANA special-purpose
  registries. It is a fixed table; keeping it current is a manual task.
- Zone ids are checked for form only, not against the interfaces of the machine.
