# Security policy

network-scanner is a defensive tool, and its safety checks (the scope policy, the limits, the
handling of hostile input) are part of what it promises. A way around them is a vulnerability.

## Reporting a vulnerability

Please report it **privately** with GitHub private vulnerability reporting: open the repository's
**Security** tab, choose **Report a vulnerability**, and describe the problem there. Do not open a
public issue or pull request for it, and do not post details anywhere public before a fix exists.

A useful report has the version (`network-scanner --version`), the operating system and Python
version, the exact command or input, what you expected, and what happened.

This is a one-person project, so there is no guaranteed response time. Reports are read and
answered as soon as the maintainer can.

## Supported versions

Only the latest release (1.0.x) receives fixes.

## What counts

In scope, for example:

- a target form or address that reaches a connection although the scope policy should refuse it
  (see [docs/scope-policy.md](docs/scope-policy.md));
- a connection made without passing the policy, or past a cap on targets, ports, concurrency,
  rate or time;
- hostile data from a scanned service, a DNS answer, a certificate, a rule file, a scope file or a
  baseline file that crashes the tool, hangs it, exhausts memory, or reaches the terminal, a file
  or a spreadsheet unsanitised (escape sequences, line breaks, formula characters);
- a way to make `--output` or a baseline write through a symbolic link, to a device, or leave a
  partial file;
- a way to make the tool send something other than what
  [the README](README.md#what-the-scanner-sends) says it sends.

Out of scope:

- scanning networks you have no permission to scan: that is misuse, not a vulnerability, and
  unauthorized scanning can be illegal;
- findings that are missing or imprecise (the scanner is not a vulnerability scanner; see the
  Limitations section of the README);
- the known gaps and limitations that the README and [docs/](docs/) already list, unless you can
  show they are worse than described;
- weaknesses in Python, the operating system or the two dependencies themselves (report those to
  their projects).

The design and its limits are described in [docs/threat-model.md](docs/threat-model.md) and
[docs/security-review.md](docs/security-review.md).
