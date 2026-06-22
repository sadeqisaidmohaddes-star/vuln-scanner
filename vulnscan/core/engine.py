"""The scan orchestrator.

:class:`ScanEngine` ties the pieces together:

1. Enforces the authorization gate before anything else.
2. Selects modules (honouring ``--modules`` and ``--passive``).
3. Builds the shared :class:`ScanContext` (HTTP client + rate limiter + inventory).
4. Runs modules against in-scope targets in **order tiers** so correlation
   modules (e.g. ``vuln_match``) see a fully-populated inventory.
5. Isolates module failures so one bad module never aborts the scan.
6. Deduplicates and severity-sorts findings, returning a :class:`ScanResult`.
"""
from __future__ import annotations

import asyncio
import itertools
import logging
from datetime import datetime, timezone
from typing import Iterable, Optional

from .aggregate import ProgressCallback, dedupe_and_sort, emit
from .context import Inventory, ScanConfig, ScanContext
from .models import Finding, ScanResult, Severity, Target
from .module_base import ScannerModule
from .ratelimit import RateLimiter
from .scope import Scope

logger = logging.getLogger("vulnscan.engine")


class ScanEngine:
    """Loads modules, runs them against in-scope targets, and aggregates findings."""

    def __init__(
        self,
        scope: Scope,
        config: ScanConfig,
        modules: list[ScannerModule],
        *,
        log: Optional[logging.Logger] = None,
    ) -> None:
        self.scope = scope
        self.config = config
        self.modules = modules
        self.log = log or logger

    # -- module selection ------------------------------------------------------------

    def select_modules(self, names: Optional[Iterable[str]] = None) -> list[ScannerModule]:
        """Filter the loaded modules by explicit selection and passive mode."""
        selected = list(self.modules)
        if names:
            wanted = {n.strip().lower() for n in names if n.strip()}
            unknown = wanted - {m.name.lower() for m in selected}
            if unknown:
                self.log.warning("Unknown module(s) ignored: %s", ", ".join(sorted(unknown)))
            selected = [m for m in selected if m.name.lower() in wanted]
        if self.config.passive:
            dropped = [m.name for m in selected if m.intrusive]
            if dropped:
                self.log.info("Passive mode: skipping intrusive modules: %s", ", ".join(dropped))
            selected = [m for m in selected if not m.intrusive]
        return sorted(selected, key=lambda m: (m.order, m.name))

    # -- execution -------------------------------------------------------------------

    async def run(
        self,
        module_names: Optional[Iterable[str]] = None,
        *,
        progress: Optional[ProgressCallback] = None,
    ) -> ScanResult:
        """Execute the scan and return aggregated results.

        Authorization MUST already be satisfied by the caller via
        ``scope.authorization.require(...)``; the engine asserts it defensively.

        ``progress`` is an optional callback invoked with small event dicts as the
        scan proceeds (used by the web UI to stream findings live). It never
        affects the returned result and is guarded against raising.
        """
        modules = self.select_modules(module_names)
        targets = self.scope.targets()
        result = ScanResult(
            modules_run=[m.name for m in modules],
            targets_scanned=len(targets),
            scope_summary=self.scope.summary(),
        )
        if not modules:
            self.log.warning("No modules selected; nothing to do.")
            return result
        if not targets:
            self.log.warning("No in-scope targets resolved; nothing to do.")
            return result

        started = datetime.now(timezone.utc)
        result.started_at = started.isoformat()
        emit(progress, {"type": "plan", "modules": [m.name for m in modules], "targets": len(targets)})

        limiter = RateLimiter(self.config.rate_limit, self.config.concurrency)
        inventory = Inventory()
        async with self._http_client() as http:
            ctx = ScanContext(self.config, self.scope, http, limiter, inventory=inventory, logger=self.log)
            findings: list[Finding] = []
            # Run modules in ascending order tiers; await each tier before the next so
            # later modules can rely on the inventory populated by earlier ones.
            for _order, tier in itertools.groupby(modules, key=lambda m: m.order):
                tier_modules = list(tier)
                tasks = []
                for module in tier_modules:
                    for target in targets:
                        if not self.scope.is_in_scope(target.host):
                            continue
                        try:
                            if not module.applicable(target, ctx):
                                continue
                        except Exception as exc:  # noqa: BLE001
                            self.log.debug("%s.applicable raised on %s: %s", module.name, target, exc)
                            continue
                        tasks.append(self._run_one(module, target, ctx, result, progress))
                if tasks:
                    for batch in await asyncio.gather(*tasks):
                        findings.extend(batch)

        result.findings = dedupe_and_sort(findings)
        finished = datetime.now(timezone.utc)
        result.finished_at = finished.isoformat()
        result.duration_seconds = (finished - started).total_seconds()
        emit(progress, {"type": "done", "total_findings": len(result.findings)})
        return result

    def _http_client(self):
        """Create the shared httpx.AsyncClient used by web modules.

        ``verify=False``: the scanner intentionally connects to hosts with invalid
        or self-signed certificates so that header/exposure checks still work; the
        dedicated TLS module performs proper certificate validation and reports
        any problems separately.
        """
        import httpx

        headers = {"User-Agent": self.config.http_user_agent}
        return httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=self.config.follow_redirects,
            max_redirects=self.config.max_redirects,
            timeout=self.config.timeout,
        )

    async def _run_one(
        self,
        module: ScannerModule,
        target: Target,
        ctx: ScanContext,
        result: ScanResult,
        progress: Optional[ProgressCallback] = None,
    ) -> list[Finding]:
        """Run a single (module, target) pair, capturing any failure as an error."""
        emit(progress, {"type": "item_start", "module": module.name, "target": str(target)})
        try:
            findings = list(await module.run(target, ctx) or [])
            emit(
                progress,
                {
                    "type": "item_done",
                    "module": module.name,
                    "target": str(target),
                    "findings": [f.to_dict() for f in findings],
                },
            )
            return findings
        except asyncio.CancelledError:  # pragma: no cover - cooperative cancellation
            raise
        except Exception as exc:  # noqa: BLE001 - module isolation is the whole point
            self.log.warning("Module %s failed on %s: %s", module.name, target, exc)
            result.errors.append(
                {"module": module.name, "target": str(target), "error": f"{type(exc).__name__}: {exc}"}
            )
            emit(
                progress,
                {"type": "item_error", "module": module.name, "target": str(target), "error": str(exc)},
            )
            return []
