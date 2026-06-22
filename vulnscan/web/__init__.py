"""FastAPI web dashboard for running live (URL) and static (repo) scans.

This is a **local / self-hosted** dashboard. Live URL scans still require an
explicit authorization attestation (mirroring the CLI ``--authorize`` gate);
repository scans are read-only static analysis of a cloned working tree.

Run it with::

    python -m vulnscan.web            # serves http://127.0.0.1:8088
    # or
    uvicorn vulnscan.web.app:app --reload
"""
from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]
