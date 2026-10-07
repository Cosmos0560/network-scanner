"""A token bucket that takes its clock and its sleeper as arguments.

Tokens refill at `rate` per second up to `capacity`. Each `acquire` takes a token at once;
if that leaves the bucket in debt, the caller sleeps exactly as long as the debt takes to
refill. Taking the token before sleeping gives every waiter its own wake-up time, so many
waiting tasks neither stampede nor starve. With the default capacity of one token, starts
are spaced at least 1/rate seconds apart, so the cap holds in every window, not only on
average. A caller that is cancelled while waiting does not give its token back, which only
ever makes the limiter more conservative.
"""

from __future__ import annotations

from network_scanner.core.interfaces import Clock, Sleeper


class TokenBucket:
    def __init__(
        self, *, rate: float, clock: Clock, sleeper: Sleeper, capacity: float = 1.0
    ) -> None:
        if not rate > 0 or not capacity >= 1:
            raise ValueError("rate must be positive and capacity at least one token")
        self._rate = rate
        self._capacity = capacity
        self._clock = clock
        self._sleeper = sleeper
        self._tokens = capacity
        self._stamp = clock.monotonic()

    async def acquire(self) -> None:
        now = self._clock.monotonic()
        self._tokens = min(self._capacity, self._tokens + (now - self._stamp) * self._rate)
        self._stamp = now
        self._tokens -= 1
        if self._tokens < 0:
            await self._sleeper.sleep(-self._tokens / self._rate)
