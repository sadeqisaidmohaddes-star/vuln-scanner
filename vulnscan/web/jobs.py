"""In-memory scan-job manager with live event streaming.

Each submitted scan becomes a :class:`Job` that runs as an asyncio task on the
server's event loop. Progress events are appended to a per-job log; SSE clients
replay the log from index 0 and then tail it until the job reaches a terminal
state, so late subscribers still see the whole scan.

In-memory state is appropriate for a single-user, self-hosted dashboard. Jobs
are evicted oldest-first once a cap is exceeded.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from ..core.models import ScanResult

logger = logging.getLogger("vulnscan.web.jobs")

# A scan coroutine receives a progress callback and returns a ScanResult.
ScanCoroutine = Callable[[Callable[[dict], None]], Awaitable[ScanResult]]


class Job:
    """A single scan job and its live event log."""

    def __init__(self, job_id: str, kind: str, target: str, modules: Optional[list[str]]) -> None:
        self.id = job_id
        self.kind = kind                 # "url" | "repo"
        self.target = target
        self.modules = modules
        self.status = "queued"           # queued | running | done | error
        self.error: Optional[str] = None
        self.result: Optional[ScanResult] = None
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.events: list[dict] = []     # append-only event log (replayable)
        self._task: Optional[asyncio.Task] = None

    # -- event log -------------------------------------------------------------------

    def push(self, event: dict) -> None:
        """Append a progress event to the log (called from the scan's callback)."""
        self.events.append(event)

    @property
    def is_terminal(self) -> bool:
        return self.status in ("done", "error")

    def summary(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "modules": self.modules,
            "status": self.status,
            "created_at": self.created_at,
            "error": self.error,
        }
        if self.result is not None:
            data["result"] = self.result.to_dict()
        return data


class JobManager:
    """Owns running jobs and exposes their lifecycle to the API layer."""

    def __init__(self, max_jobs: int = 100) -> None:
        self._jobs: "OrderedDict[str, Job]" = OrderedDict()
        self._max_jobs = max_jobs

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def create(self, kind: str, target: str, modules: Optional[list[str]], scan: ScanCoroutine) -> Job:
        """Register a job and launch its scan coroutine as a background task."""
        job_id = uuid.uuid4().hex[:12]
        job = Job(job_id, kind, target, modules)
        self._jobs[job_id] = job
        self._evict_if_needed()
        job._task = asyncio.create_task(self._run(job, scan))
        return job

    async def _run(self, job: Job, scan: ScanCoroutine) -> None:
        job.status = "running"
        try:
            result = await scan(job.push)
            job.result = result
            job.status = "done"
            job.push({"type": "complete", "status": "done", "result": result.to_dict()})
        except asyncio.CancelledError:  # pragma: no cover
            job.status = "error"
            job.error = "cancelled"
            job.push({"type": "complete", "status": "error", "error": "cancelled"})
            raise
        except Exception as exc:  # noqa: BLE001 - surface any failure to the client
            logger.warning("Job %s failed: %s", job.id, exc)
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.push({"type": "complete", "status": "error", "error": job.error})

    def _evict_if_needed(self) -> None:
        while len(self._jobs) > self._max_jobs:
            old_id, _ = self._jobs.popitem(last=False)
            logger.debug("Evicted old job %s", old_id)

    async def stream(self, job: Job, *, poll: float = 0.2):
        """Async generator of SSE ``data:`` frames for a job (replay + tail)."""
        import json

        sent = 0
        while True:
            while sent < len(job.events):
                yield f"data: {json.dumps(job.events[sent])}\n\n"
                sent += 1
            if job.is_terminal and sent >= len(job.events):
                break
            await asyncio.sleep(poll)
