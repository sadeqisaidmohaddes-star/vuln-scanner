"""Async rate limiting and concurrency control.

:class:`RateLimiter` combines two independent throttles that every network
operation should pass through:

* a **token bucket** that caps the *rate* of new operations (requests/sec), and
* a **semaphore** that caps the *number of concurrent* operations.

Modules acquire both at once via the :meth:`slot` async context manager::

    async with limiter.slot():
        await do_one_network_thing()
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from typing import AsyncIterator, Callable


class RateLimiter:
    """Token-bucket rate limiter plus a concurrency semaphore.

    Parameters
    ----------
    rate_per_sec:
        Maximum sustained operations per second. ``0`` or negative disables the
        rate gate (concurrency limiting still applies).
    concurrency:
        Maximum number of operations allowed to hold a slot simultaneously.
    burst:
        Bucket capacity (max tokens that can accumulate). Defaults to roughly one
        second's worth of tokens, with a floor of 1.
    time_fn:
        Monotonic clock, injectable for testing.
    """

    def __init__(
        self,
        rate_per_sec: float,
        concurrency: int,
        *,
        burst: float | None = None,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        self.rate = max(0.0, float(rate_per_sec))
        self.concurrency = max(1, int(concurrency))
        self.capacity = float(burst) if burst is not None else max(1.0, self.rate)
        self._tokens = self.capacity
        self._sem = asyncio.Semaphore(self.concurrency)
        self._lock = asyncio.Lock()
        self._time = time_fn or time.monotonic
        self._updated = self._time()

    async def _acquire_token(self) -> None:
        """Block until a single token is available, then consume it."""
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = self._time()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Sleep just long enough for the next token to accrue.
                await asyncio.sleep((1.0 - self._tokens) / self.rate)

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Acquire a concurrency slot and a rate token for the duration of the block."""
        async with self._sem:
            await self._acquire_token()
            yield
