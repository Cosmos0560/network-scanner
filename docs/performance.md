# Performance and timing measurements

This is the only document that contains measured numbers. They come from one run on one
machine, they were pasted by hand from the script output, and no test regenerates them.
Treat them as an observation, not as a specification.

## Question

On Windows a connection to a closed port can take about two seconds to be refused, because
the operating system retries the connection attempt before it gives up. A scanner whose
connect timeout is shorter than that would report closed ports as `filtered`
(risk R2 in [PLAN.md](../PLAN.md)). Section 0 of the plan says to keep the proposed default
connect timeout until it has been measured. The question is therefore: how long does a
refused connection take on this machine, compared with the default timeout?

## Method

`scripts/measure_connect.py`, run as `python scripts/measure_connect.py --samples 10
--concurrent 64`. For each of the two loopback addresses (`127.0.0.1` and `::1`; any other
host is refused by the script) it:

1. creates, on OS-assigned ports, one listening socket (an "open" port), one socket that is
   bound but never listens (a "closed" port), and 64 more closed sockets;
2. times 10 sequential connects to the open port and 10 to the closed port, using
   `time.perf_counter()` around `asyncio.open_connection`, which is the call the scanner's
   connector uses, on the default event loop of the platform;
3. times one batch of 64 concurrent connects to the 64 closed sockets, as a whole and
   individually;
4. uses a probe timeout of 30 s, far above anything expected, so that the true latency of a
   refusal is visible instead of being cut off.

Nothing leaves the machine: the only addresses used are `127.0.0.1` and `::1`.

## Environment

| | |
|---|---|
| Date | 2026-10-07 |
| Platform | Windows-11-10.0.26300-SP0 |
| Python | 3.13.14 |
| Event loop | `ProactorEventLoop` (the default on Windows) |
| Default connect timeout in the code at the time | 3.0 s |

## Results

All values are milliseconds, from the output of the run described above.

| Case | Samples | Min | Median | Max | How it ended |
|------|---------|-----|--------|-----|--------------|
| `127.0.0.1` open port | 10 | 0.1 | 0.1 | 0.4 | connected |
| `127.0.0.1` closed port | 10 | 2041.0 | 2050.6 | 2057.7 | `ConnectionRefusedError`, winerror 1225 |
| `127.0.0.1` 64 concurrent closed ports | 64 | 2046.5 | 2048.4 | 2057.6 | `ConnectionRefusedError`, winerror 1225 |
| `::1` open port | 10 | 0.6 | 0.8 | 1.3 | connected |
| `::1` closed port | 10 | 2025.8 | 2046.3 | 2054.2 | `ConnectionRefusedError`, winerror 1225 |
| `::1` 64 concurrent closed ports | 64 | 2044.1 | 2050.8 | 2057.6 | `ConnectionRefusedError`, winerror 1225 |

The whole batch of 64 concurrent refusals took 2069.6 ms on `127.0.0.1` and 2071.9 ms on
`::1`. The slowest single refusal in the run was 2057.7 ms.

## What the results show

- A refused loopback connection takes about two seconds on this machine, for both address
  families, as the plan expected. Opening a connection to a listening port is orders of
  magnitude faster.
- Concurrent refusals overlap. 64 of them together took barely longer than one, so a scan of
  many closed ports is not slowed in proportion to their number by this delay.
- The default connect timeout of 3.0 s is longer than the slowest refusal seen here, by
  about 0.9 s. **The default is kept.** A timeout below roughly two seconds would turn
  closed ports into `filtered` on this machine; the `--connect-timeout` option allows it, so
  the option's help text points here.

## What this does not show

- Linux. The scanner's CI runs on Linux too, but nothing was measured there, and no claim is
  made about Linux timing.
- Other Windows versions, other network stacks, or a machine under load. The refusal delay
  is a property of the operating system's retry behaviour, and this is one observation of it.
- Real networks. Loopback has no distance, loss or filtering. A `filtered` result (no answer
  at all) cannot be produced on loopback without firewall rules, so the timeout path is
  tested with an injected connector on virtual time, and real dropped packets are listed as
  not verified.
- Scan throughput. No whole-scan speed measurement was made.

## Reproducing

```
python scripts/measure_connect.py --samples 10 --concurrent 64
```

Expect run times of about a minute on Windows because of the delay itself.

## Regular expressions: worst accepted patterns (Phase 4)

Rule files contain regular expressions, and Python's `re` has no timeout. The validator
(`src/network_scanner/rules/regex_safety.py`, described in [architecture.md](architecture.md))
accepts a pattern only if its estimated backtracking stays within a budget, and a pattern only
ever sees the first 256 characters of its input. Question: how slow can a pattern that is
accepted be, on the worst input?

### Method

Each pattern below is accepted by the validator, was compiled with `compile_safe`, and was run
with `search_bounded` on an input chosen so that the match fails after as much backtracking as
the pattern allows. Nine runs each, timed with `time.perf_counter()` around the call, sorted.

```python
import time
from network_scanner.rules.regex_safety import compile_safe, search_bounded

compiled = compile_safe(r".*.*x")
runs = []
for _ in range(9):
    start = time.perf_counter()
    search_bounded(compiled, "a" * 256)
    runs.append((time.perf_counter() - start) * 1000)
runs.sort()
print(runs[0], runs[4], runs[-1])
```

### Results

Same machine as above (Windows 11, Python 3.13.14, 2026-10-08). Milliseconds.

| Pattern | Input | Min | Median | Max |
|---------|-------|-----|--------|-----|
| `.*.*x` | 256 x `a` | 2.4 | 2.8 | 4.6 |
| `[a-z]*[a-z]*!` | 256 x `a` | 5.6 | 6.0 | 7.6 |
| `(a\|a)` x 16, then `b` | 16 x `a`, then `c` | 2.4 | 2.4 | 2.7 |
| `a?` x 16, `a` x 16, then `b` | 16 x `a` | 0.0 | 0.0 | 0.0 |

The last row is below the resolution of the print format (0.05 ms); `re` rejects that input
early.

### What this shows, and what it does not

- Patterns the validator accepts cost a few milliseconds per match in the worst cases tried.
  An earlier version of the check, which only limited the number of unbounded repeats, accepted
  `.*.*.*x`, which took about 200 ms per match on the same input; that is why the check now
  multiplies every choice into a budget instead.
- This is four hand-picked patterns, not a proof. The bound comes from the cost estimate and
  the input cap; these numbers only show that the estimate is not wildly optimistic for the
  shapes that are known to be dangerous. Other Python versions and other `re` builds were not
  measured.
