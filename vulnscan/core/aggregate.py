"""Shared finding-aggregation helpers used by both the live and static engines.

Keeping dedupe/sort in one place means the network scanner and the static
repository scanner collapse and rank findings identically.
"""
from __future__ import annotations

from typing import Callable, Optional

from .models import Finding

# A progress callback receives small JSON-serialisable event dicts as the scan
# proceeds (used by the web UI to stream results live). It must never raise.
ProgressCallback = Callable[[dict], None]


def dedupe_and_sort(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings by ``dedupe_key`` and sort by descending severity."""
    unique: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        unique.setdefault(f.dedupe_key, f)
    return sorted(
        unique.values(),
        key=lambda f: (-int(f.severity), f.module, f.target, f.title),
    )


def emit(progress: Optional[ProgressCallback], event: dict) -> None:
    """Safely invoke a progress callback, swallowing any error it raises."""
    if progress is None:
        return
    try:
        progress(event)
    except Exception:  # noqa: BLE001 - progress reporting must never break a scan
        pass
