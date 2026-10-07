"""An asyncio event loop that runs on virtual time, so timing tests never sleep.

`loop.time()` is a counter. Whenever the loop would wait for the next timer, it jumps the
counter forward by exactly that much instead of blocking. `asyncio.sleep`, `wait_for`,
`asyncio.timeout` and the rate limiter therefore all see time that advances only when every
task is waiting, which makes ordering and elapsed time exact and repeatable.

A loop that has nothing scheduled and nothing ready would wait forever; here that is a test
failure (`DeadlockError`) instead of a hang. Real sockets still work (the selector is polled
without blocking), but a test must not wait on them, because nothing would ever wake it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


class DeadlockError(RuntimeError):
    pass


class VirtualTimeLoop(asyncio.SelectorEventLoop):
    def __init__(self) -> None:
        super().__init__()
        self._virtual_now = 0.0
        # Windows' monotonic clock has a 15.6 ms resolution, which would merge nearby timers.
        # A timer is due when `when < now + resolution`, so it must be above zero for a timer
        # that lands exactly on `now` to fire.
        setattr(self, "_clock_resolution", 1e-9)  # noqa: B010
        selector: Any = getattr(self, "_selector")  # noqa: B009
        real_select = selector.select

        def select(timeout: float | None = None) -> list[Any]:
            if timeout is None:
                raise DeadlockError("the event loop would wait forever")
            target = self._virtual_now + max(timeout, 0.0)
            scheduled: list[Any] = getattr(self, "_scheduled", [])
            if scheduled and abs(scheduled[0]._when - target) < 1e-6:
                # Land exactly on the timer: `now + (when - now)` can round back to `now`
                # for large times, and the loop would then spin without ever advancing.
                target = scheduled[0]._when
            self._virtual_now = target
            events: list[Any] = real_select(0)
            return events

        selector.select = select

    def time(self) -> float:
        return self._virtual_now


def run_virtual(main: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run `main()` to completion on a fresh virtual-time loop, then insist nothing is left."""
    loop = VirtualTimeLoop()
    try:
        result = loop.run_until_complete(main())
        leftover = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in leftover:
            task.cancel()
        if leftover:
            loop.run_until_complete(asyncio.gather(*leftover, return_exceptions=True))
            raise AssertionError(f"{len(leftover)} task(s) were still running at the end")
        loop.run_until_complete(loop.shutdown_asyncgens())
        return result
    finally:
        loop.close()
