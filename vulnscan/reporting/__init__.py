"""Report renderers for scan results.

This package defines the stable reporting API used by the CLI:

* :func:`render_console` — colorized text for the terminal.
* :func:`render_json` / :func:`write_json` — machine-readable JSON.
* :func:`render_html` / :func:`write_html` — standalone HTML report.

Each renderer lives in its own submodule (``console``, ``json_report``,
``html_report``) and operates purely on a :class:`vulnscan.core.models.ScanResult`.
"""
from __future__ import annotations

from .console import render_console
from .html_report import render_html, write_html
from .json_report import render_json, write_json

__all__ = [
    "render_console",
    "render_json",
    "write_json",
    "render_html",
    "write_html",
]
