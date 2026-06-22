"""Runtime context shared with every scanner module during a scan.

A single :class:`ScanContext` is created by the engine and passed to each
module's ``run`` method. It exposes:

* ``config``   — the resolved :class:`ScanConfig`.
* ``scope``    — the active :class:`~vulnscan.core.scope.Scope`.
* ``http``     — a shared ``httpx.AsyncClient`` (and rate-limited helpers).
* ``inventory``— a cross-module store of observed services/versions, written by
  discovery modules (port/TLS/HTTP) and consumed by ``vuln_match``.
* ``limiter``  — the global :class:`RateLimiter`.

All network egress should go through the rate-limited helpers (``http_request``,
``http_get``, ``open_connection``) or be wrapped in ``async with ctx.slot()`` so
the configured rate limit and concurrency cap are honoured.
"""
from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, AsyncIterator, Optional

from .ratelimit import RateLimiter

if TYPE_CHECKING:  # avoid hard import cycle / optional dependency at import time
    import httpx

    from .scope import Scope


@dataclass
class ScanConfig:
    """Resolved, immutable-ish configuration for a scan run."""

    rate_limit: float = 10.0
    concurrency: int = 20
    timeout: float = 10.0
    passive: bool = False
    verbose: bool = False
    http_user_agent: str = "vulnscan/0.1 (+authorized-security-assessment)"
    follow_redirects: bool = True
    max_redirects: int = 3
    # Per-module knobs (wordlist paths, port lists, etc.) live here, keyed by module name.
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceObservation:
    """A single observed network service, contributed to the shared inventory."""

    host: str
    port: Optional[int] = None
    service: str = ""          # e.g. "http", "ssh", "mysql"
    product: str = ""          # e.g. "nginx", "OpenSSH", "Apache"
    version: str = ""          # e.g. "1.18.0"
    source: str = ""           # module name that observed it
    raw_banner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "source": self.source,
            "raw_banner": self.raw_banner,
        }


class Inventory:
    """Thread/async-safe collection of :class:`ServiceObservation` records."""

    def __init__(self) -> None:
        self._services: list[ServiceObservation] = []

    def add(self, obs: ServiceObservation) -> None:
        """Record an observation. Safe to call from within the event loop."""
        self._services.append(obs)

    @property
    def services(self) -> list[ServiceObservation]:
        return list(self._services)

    def for_host(self, host: str) -> list[ServiceObservation]:
        return [s for s in self._services if s.host == host]

    def __len__(self) -> int:
        return len(self._services)


class ScanContext:
    """Per-scan shared state and rate-limited network helpers handed to modules."""

    def __init__(
        self,
        config: ScanConfig,
        scope: "Scope",
        http_client: "httpx.AsyncClient",
        limiter: RateLimiter,
        *,
        inventory: Optional[Inventory] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.http = http_client
        self.limiter = limiter
        self.inventory = inventory or Inventory()
        self.log = logger or logging.getLogger("vulnscan")

    # -- concurrency / rate limiting -------------------------------------------------

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Acquire a rate token + concurrency slot for one network operation."""
        async with self.limiter.slot():
            yield

    # -- HTTP helpers ----------------------------------------------------------------

    async def http_request(self, method: str, url: str, **kwargs: Any) -> "httpx.Response":
        """Rate-limited ``httpx`` request. ``timeout`` defaults to the config value."""
        kwargs.setdefault("timeout", self.config.timeout)
        async with self.slot():
            return await self.http.request(method, url, **kwargs)

    async def http_get(self, url: str, **kwargs: Any) -> "httpx.Response":
        return await self.http_request("GET", url, **kwargs)

    async def http_head(self, url: str, **kwargs: Any) -> "httpx.Response":
        return await self.http_request("HEAD", url, **kwargs)

    # -- raw TCP helper --------------------------------------------------------------

    async def open_connection(self, host: str, port: int, *, timeout: Optional[float] = None):
        """Rate-limited ``asyncio.open_connection`` returning ``(reader, writer)``.

        The slot is held only for the duration of the connect; callers own the
        returned streams and are responsible for closing them.
        """
        import asyncio

        async with self.slot():
            return await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout or self.config.timeout,
            )

    # -- inventory convenience -------------------------------------------------------

    def record_service(
        self,
        host: str,
        *,
        port: Optional[int] = None,
        service: str = "",
        product: str = "",
        version: str = "",
        source: str = "",
        raw_banner: str = "",
    ) -> None:
        """Add a service observation to the shared inventory (used by ``vuln_match``)."""
        self.inventory.add(
            ServiceObservation(
                host=host,
                port=port,
                service=service,
                product=product,
                version=version,
                source=source,
                raw_banner=raw_banner,
            )
        )
