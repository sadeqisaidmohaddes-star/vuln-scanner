"""JSON reporter for scan results.

This module renders a :class:`~vulnscan.core.models.ScanResult` into the
machine-readable JSON document produced by ``ScanResult.to_dict``. The
functions here are pure: :func:`render_json` performs no I/O, and
:func:`write_json` only writes the requested file (creating parent
directories as needed). Both depend solely on the standard library.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render a scan result as a pretty-printed JSON string.

    Args:
        result: The completed scan result to serialise.

    Returns:
        A two-space-indented JSON document. Non-ASCII characters are
        preserved verbatim (``ensure_ascii=False``) so the output is
        UTF-8 friendly.
    """
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def write_json(result: ScanResult, path: str | Path) -> None:
    """Write the JSON report for ``result`` to ``path`` as UTF-8.

    Any missing parent directories are created before writing.

    Args:
        result: The completed scan result to serialise.
        path: Destination file path (``str`` or :class:`~pathlib.Path`).
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_json(result), encoding="utf-8")
