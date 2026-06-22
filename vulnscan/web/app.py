"""FastAPI application exposing the scan dashboard and its JSON/SSE API.

Routes
------
GET  /                       -> the single-page UI
GET  /api/health             -> liveness probe
GET  /api/modules            -> available live + static modules
POST /api/scan               -> submit a scan, returns {job_id, kind, target}
GET  /api/scan/{id}          -> job status (+ result when finished)
GET  /api/scan/{id}/events   -> Server-Sent Events stream of live progress
GET  /api/scan/{id}/report.json
GET  /api/scan/{id}/report.html
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .jobs import JobManager
from .service import detect_kind, list_modules, run_repo_scan, run_url_scan

logger = logging.getLogger("vulnscan.web")

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> "object":
    """Build and return the FastAPI application (imported lazily so core stays light)."""
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel

    STATIC_DIR.mkdir(parents=True, exist_ok=True)  # ensure mountable even before the UI is built

    app = FastAPI(
        title="vulnscan dashboard",
        description="Local dashboard for authorized live (URL) and static (repo) vulnerability scans.",
        version="0.1.0",
    )
    jobs = JobManager()

    class ScanRequest(BaseModel):
        target: str
        kind: str = "auto"                  # auto | url | repo
        modules: Optional[list[str]] = None
        passive: bool = False
        authorized: bool = False
        token: Optional[str] = None
        ref: Optional[str] = None
        rate_limit: float = 10.0
        concurrency: int = 20

    # -- UI --------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index() -> "HTMLResponse":
        index_file = STATIC_DIR / "index.html"
        if index_file.is_file():
            return HTMLResponse(index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>vulnscan</h1><p>UI not built yet.</p>", status_code=200)

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok", "service": "vulnscan", "version": "0.1.0"}

    @app.get("/api/modules")
    async def modules() -> dict:
        return list_modules()

    # -- scan submission -------------------------------------------------------------

    @app.post("/api/scan")
    async def submit_scan(req: ScanRequest) -> JSONResponse:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="A target URL or repository is required.")
        kind = req.kind if req.kind in ("url", "repo") else detect_kind(target)

        if kind == "url" and not req.authorized:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Live URL scans require authorization. Confirm you hold explicit "
                    "written permission to test this target (set 'authorized': true)."
                ),
            )

        if kind == "url":
            async def scan(progress):
                return await run_url_scan(
                    target,
                    modules=req.modules,
                    passive=req.passive,
                    authorized=req.authorized,
                    rate_limit=req.rate_limit,
                    concurrency=req.concurrency,
                    progress=progress,
                )
        else:
            async def scan(progress):
                return await run_repo_scan(
                    target, modules=req.modules, token=req.token, ref=req.ref, progress=progress
                )

        job = jobs.create(kind, target, req.modules, scan)
        return JSONResponse({"job_id": job.id, "kind": kind, "target": target}, status_code=202)

    # -- job status / streaming ------------------------------------------------------

    def _require_job(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Unknown job id.")
        return job

    @app.get("/api/scan/{job_id}")
    async def job_status(job_id: str) -> dict:
        return _require_job(job_id).summary()

    @app.get("/api/scan/{job_id}/events")
    async def job_events(job_id: str) -> "StreamingResponse":
        job = _require_job(job_id)
        return StreamingResponse(
            jobs.stream(job),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/scan/{job_id}/report.json")
    async def report_json(job_id: str) -> JSONResponse:
        job = _require_job(job_id)
        if job.result is None:
            raise HTTPException(status_code=409, detail="Scan not finished.")
        return JSONResponse(job.result.to_dict())

    @app.get("/api/scan/{job_id}/report.html", response_class=HTMLResponse)
    async def report_html(job_id: str) -> "HTMLResponse":
        job = _require_job(job_id)
        if job.result is None:
            raise HTTPException(status_code=409, detail="Scan not finished.")
        from ..reporting import render_html

        return HTMLResponse(render_html(job.result))

    # Mount static assets last so /api/* and / take precedence.
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


# Module-level app for `uvicorn vulnscan.web.app:app`.
app = create_app()
