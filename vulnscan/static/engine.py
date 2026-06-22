"""Static-scan orchestrator.

Mirrors :class:`vulnscan.core.engine.ScanEngine` for source repositories: it
discovers :class:`StaticModule` subclasses, runs each over a
:class:`RepoContext`, isolates failures, streams progress, and returns the same
:class:`~vulnscan.core.models.ScanResult` used by the network scanner.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..core.aggregate import ProgressCallback, dedupe_and_sort, emit
from ..core.models import Finding, ScanResult
from ..core.registry import discover_modules
from .context import RepoContext, StaticConfig
from .module_base import StaticModule

logger = logging.getLogger("vulnscan.static.engine")

STATIC_PACKAGES = ("vulnscan.static.modules",)


def discover_static_modules(
    *,
    extra_dirs: Optional[Iterable[str]] = None,
    log: Optional[logging.Logger] = None,
) -> list[StaticModule]:
    """Discover all built-in (and extra-dir) static modules."""
    return discover_modules(STATIC_PACKAGES, extra_dirs=extra_dirs, log=log, base=StaticModule)


class StaticEngine:
    """Runs static modules against a prepared repository working tree."""

    def __init__(
        self,
        config: StaticConfig,
        modules: list[StaticModule],
        *,
        log: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.modules = modules
        self.log = log or logger

    def select_modules(self, names: Optional[Iterable[str]] = None) -> list[StaticModule]:
        selected = list(self.modules)
        if names:
            wanted = {n.strip().lower() for n in names if n.strip()}
            unknown = wanted - {m.name.lower() for m in selected}
            if unknown:
                self.log.warning("Unknown static module(s) ignored: %s", ", ".join(sorted(unknown)))
            selected = [m for m in selected if m.name.lower() in wanted]
        return sorted(selected, key=lambda m: (m.order, m.name))

    async def run(
        self,
        repo: RepoContext,
        module_names: Optional[Iterable[str]] = None,
        *,
        progress: Optional[ProgressCallback] = None,
    ) -> ScanResult:
        """Run the selected static modules over ``repo`` and aggregate findings."""
        modules = self.select_modules(module_names)
        result = ScanResult(
            modules_run=[m.name for m in modules],
            targets_scanned=1,
            scope_summary={"repository": repo.meta.to_dict()},
        )
        if not modules:
            self.log.warning("No static modules selected; nothing to do.")
            return result

        started = datetime.now(timezone.utc)
        result.started_at = started.isoformat()
        emit(progress, {"type": "plan", "modules": [m.name for m in modules], "targets": 1})

        async def run_one(module: StaticModule) -> list[Finding]:
            emit(progress, {"type": "item_start", "module": module.name, "target": repo.meta.label})
            try:
                if not module.applicable(repo):
                    emit(progress, {"type": "item_done", "module": module.name,
                                    "target": repo.meta.label, "findings": []})
                    return []
                findings = list(await module.run(repo) or [])
                emit(progress, {"type": "item_done", "module": module.name,
                                "target": repo.meta.label,
                                "findings": [f.to_dict() for f in findings]})
                return findings
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:  # noqa: BLE001 - module isolation
                self.log.warning("Static module %s failed: %s", module.name, exc)
                result.errors.append(
                    {"module": module.name, "target": repo.meta.label,
                     "error": f"{type(exc).__name__}: {exc}"}
                )
                emit(progress, {"type": "item_error", "module": module.name,
                                "target": repo.meta.label, "error": str(exc)})
                return []

        all_findings: list[Finding] = []
        for batch in await asyncio.gather(*(run_one(m) for m in modules)):
            all_findings.extend(batch)

        result.findings = dedupe_and_sort(all_findings)
        finished = datetime.now(timezone.utc)
        result.finished_at = finished.isoformat()
        result.duration_seconds = (finished - started).total_seconds()
        emit(progress, {"type": "done", "total_findings": len(result.findings)})
        return result
