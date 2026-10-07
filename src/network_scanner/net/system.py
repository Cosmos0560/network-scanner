"""The real clock and sleeper. Decision logic never imports these; the CLI injects them."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utc_now(self) -> datetime:
        return datetime.now(UTC)


class AsyncioSleeper:
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
