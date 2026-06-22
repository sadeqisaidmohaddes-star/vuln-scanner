"""End-to-end tests for the FastAPI web dashboard (vulnscan.web.app).

These are fully OFFLINE: the only scan exercised is a *static* (repo) scan against
a local directory built under ``tmp_path``. ``prepare_repo`` wraps an existing
local directory in place (no git clone, no network), and the static modules that
fire here (``sensitive_files`` on a committed ``.env`` and ``secrets`` on source
files) read files only — they never touch the network.

The whole module is skipped unless FastAPI (and its Starlette ``TestClient``) is
installed, so it is a no-op in the lean default install.
"""
from __future__ import annotations

import time

import pytest

# Skip the entire module unless the optional web stack is available.
fastapi = pytest.importorskip("fastapi")
# TestClient lives in Starlette and requires httpx; importorskip both so a
# partial install skips cleanly rather than erroring at collection time.
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402  (after importorskip guard)

from vulnscan.web.app import create_app  # noqa: E402


# These tests drive the app through synchronous TestClient requests. TestClient
# runs the ASGI app on a background event-loop portal, so the fire-and-forget
# scan task created inside POST /api/scan keeps making progress between the
# separate (blocking) status-poll requests below.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture()
def client():
    with TestClient(create_app()) as c:
        yield c


def _build_local_repo(tmp_path):
    """Create a minimal local repo dir that triggers static findings, no network.

    A committed ``.env`` reliably fires the ``sensitive_files`` module (HIGH,
    category ``env_file``). ``requirements.txt`` pins a known-old dependency; it
    is included per the scenario even though the offline run's guaranteed finding
    comes from the sensitive file.
    """
    repo = tmp_path / "localrepo"
    repo.mkdir()
    (repo / ".env").write_text(
        "DATABASE_URL=postgres://user:supersecret@db.internal:5432/app\n"
        "API_KEY=abcd1234efgh5678\n",
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    # A little source so the secrets module has text files to scan as well.
    (repo / "app.py").write_text(
        "import os\n\nDEBUG = os.environ.get('DEBUG')\n",
        encoding="utf-8",
    )
    return repo


# -- simple endpoints --------------------------------------------------------------


def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


def test_modules_lists_live_and_static(client):
    resp = client.get("/api/modules")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("live"), list) and len(body["live"]) >= 1
    assert isinstance(body.get("static"), list) and len(body["static"]) >= 1
    # Each entry carries the descriptive metadata the UI renders.
    for entry in body["live"] + body["static"]:
        assert "name" in entry and "description" in entry


def test_url_scan_requires_authorization(client):
    resp = client.post(
        "/api/scan",
        json={"target": "example.com", "kind": "url", "authorized": False},
    )
    assert resp.status_code == 403


# -- full local (offline) repo scan ------------------------------------------------


def test_repo_scan_against_local_dir(client, tmp_path):
    repo = _build_local_repo(tmp_path)

    submit = client.post("/api/scan", json={"target": str(repo), "kind": "repo"})
    assert submit.status_code == 202, submit.text
    submitted = submit.json()
    job_id = submitted["job_id"]
    assert job_id
    assert submitted["kind"] == "repo"

    # Poll the job until it reaches a terminal state. TestClient blocks on each
    # request, and the scan task advances on the app's loop in between, so this
    # short bounded loop is enough for a tiny local-dir scan.
    status_body = None
    for _ in range(50):
        status_resp = client.get(f"/api/scan/{job_id}")
        assert status_resp.status_code == 200
        status_body = status_resp.json()
        if status_body["status"] in ("done", "error"):
            break
        time.sleep(0.1)

    assert status_body is not None
    assert status_body["status"] == "done", (
        f"scan did not finish cleanly: {status_body.get('status')!r} "
        f"error={status_body.get('error')!r}"
    )

    result = status_body["result"]
    assert result["summary"]["total_findings"] >= 1

    modules_seen = {f["module"] for f in result["findings"]}
    assert modules_seen & {"secrets", "sensitive_files", "dependencies"}, (
        f"expected a finding from secrets/sensitive_files/dependencies, "
        f"got modules: {sorted(modules_seen)}"
    )

    # The JSON report endpoint serves the same completed result.
    report = client.get(f"/api/scan/{job_id}/report.json")
    assert report.status_code == 200
    report_body = report.json()
    assert report_body["summary"]["total_findings"] >= 1
    assert report_body["tool"] == "vulnscan"
