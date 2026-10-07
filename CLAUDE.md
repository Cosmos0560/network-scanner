# CLAUDE.md - network-scanner

Defensive TCP connect scanner and attack-surface drift monitor for home labs and
networks the user is authorized to test. Flagship repo #2 of a cybersecurity portfolio.
Author: Otabek Yakubov (GitHub: Cosmos0560). Goal: SOC / blue-team hiring managers can
clone and run it in two minutes. "Perfect" = correct, tested, documented, truthful. Not big.
The approved plan lives in PLAN.md. Do not import anything from the author's other repos.

## Workflow
- No code before PLAN.md is approved by Otabek.
- Per phase: small increments -> gate -> commit -> 5-line report (built, tests added,
  real whole-project coverage, known gaps, deviations) -> STOP and wait for "continue".
- Anything fails twice: stop and explain the root cause. Never patch around it.
- Flaky test: find the root cause, run it many times. Never add retries.
- No scope creep. v1.0 scope and the out-of-scope list are fixed in PLAN.md.
- Final gate before 1.0: fresh-clone test, README claim -> evidence table, pip-audit and
  bandit in a temporary venv OUTSIDE the repo, then a list of what was NOT verified.

## Git
- Commit only via `python scripts/gate.py && git commit ...`.
- Small Conventional Commits, one logical change each.
- Stage by explicit path only. Never `git add -A` or `git add .`.
- Never `git push`. Never create tags. Otabek pushes.
- Never change the git identity. Never write an email address in any file.
  Identity in files: "Otabek Yakubov" and Cosmos0560 only.
- CI is green only when Otabek reports the Actions result. Never claim it otherwise.

## Gate (scripts/gate.py), all must pass before every commit
1. ruff check
2. ruff format --check
3. mypy --platform linux AND mypy --platform win32
4. scripts/check_architecture.py (AST-based, paths via as_posix(), also runs inside pytest)
5. pytest with coverage threshold 85% (report the real measured number)

## Machine rules (Windows 11, VS Code, Git Bash)
- Default Python may be 3.14. Use Python 3.13 via uv. ONE `.venv` only.
  No extra venvs for other versions (CI covers them). A temporary one must be deleted.
- Disk is nearly full: leave no temp files, Docker images or containers behind.
- Never touch the existing Docker containers (WordPress stack, dvwa). Never run any
  `docker ... prune`. Never use host port 8080. Never kill processes by image name.
  If Docker is ever needed: create and remove only resources named network-scanner-verify*.
- Network access for the assistant: PyPI only (Docker Hub only if a Docker check is needed).
  Never contact any other host.
- Do NOT run /graphify in this project until asked. Keep graphify-out/ in .gitignore.
- Request keep-awake during long runs.

## Safety design (non-negotiable)
- Defensive tool. Default scope: loopback, RFC 1918, IPv6 ULA and IPv6 link-local.
  Everything else is refused by default.
- Public address needs ALL of: --allow-public, an entry in the scope file, and a
  confirmation (--yes or interactive prompt).
- Always refused: multicast, broadcast, reserved ranges, ambiguous numeric IP forms
  (decimal, hex, octal, short forms), IPv4-mapped IPv6 and similar embeddings.
- Hostnames are resolved ONCE, answers pinned, EVERY answer checked against the policy.
  One bad answer refuses the whole hostname. Connect to the pinned IP, never the name.
- All targets are validated before the first connection is made (fail closed).
- Hard caps on targets per run, ports per target, concurrency and connection rate.
- No raw sockets, no admin rights, no stealth or evasion (decoys, spoofing, fragmentation,
  timing tricks), no exploitation, no credential testing, no CVE matching, no
  internet-wide scanning. Probes: passive banner read and minimal benign requests only.
- Tests, demo and doc examples never contact a non-loopback host. Test servers bind
  127.0.0.1 on ephemeral ports. Docs may use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- README and docs carry the notice: scan only networks you own or have written
  permission to scan; unauthorized scanning can be illegal.

## Engineering rules
- Layered architecture, import direction enforced by scripts/check_architecture.py.
- Determinism: no wall clock, randomness or real network inside decision logic.
  Inject clocks, sleepers, resolvers and connectors.
- Everything from the network is untrusted (banners, certificates, DNS answers):
  size caps, timeouts, strip ANSI / CR / LF / bidi / NUL / control characters before
  display or storage. Never build shell commands or HTML from it.
- Dependencies: default answer is no. Prefer the standard library. Every dependency
  needs a written reason in docs/architecture.md.
- YAML is loaded with yaml.safe_load only, with a file size cap.

## Truthfulness
- Never claim a result that was not actually run.
- Every README claim links to the test or doc that proves it.
- No test count, coverage figure or speed number anywhere except docs/performance.md.
- Generated tables get a drift test.
- README demo output is pasted from a real run.
- ATT&CK or other references only where they can be stated precisely; otherwise omit.

## Cross-platform traps (develop on Windows, CI on Linux and Windows)
- Always pass encoding="utf-8" (and newline where it matters) to open().
- Use Path.as_posix() for anything compared, stored or printed; never str(Path).
- Windows-only APIs sit behind `sys.platform` guards so mypy passes on both platforms.
- Do not trust urllib parsing for security decisions; validate authorities ourselves.
- Linux reuses inodes immediately; never use them as identity.
- Windows asyncio uses the Proactor loop: no add_signal_handler, different errors on
  reset and refused connections. Normalise OS errors into our own enum.
- Windows may take about 2 s to report a refused connection; see PLAN.md risk R2.

## CI (.github/workflows/ci.yml, exists from Phase 1)
- ubuntu-24.04 and windows-latest x Python 3.11 / 3.12 / 3.13.
- permissions: contents: read. Pinned action majors. concurrency: cancel-in-progress.

## Testing
- Deterministic pytest. No sleeps as synchronisation, no real DNS, no non-loopback hosts.
- Adversarial suite: hostile servers (endless banner, slow drip, ANSI and control chars,
  invalid UTF-8, TLS garbage, accept-then-close, RST), scope bypass (numeric forms,
  IPv4-mapped IPv6, mixed private/public DNS answers, CIDR overflow, huge target lists),
  hostile CLI arguments (NUL bytes, UNC paths, huge values), output injection.
- End-to-end tests against the local mock lab with exact expected results.

## Layout (details in PLAN.md)
src/network_scanner/{core,scope,ports,net,rules,engine,fingerprint,findings,baseline,output,lab,cli}
scripts/{gate.py,check_architecture.py}  tests/  docs/  .github/workflows/ci.yml
