"""Helpers for locating and loading bundled data files (wordlists, signature DBs).

Modules should load their wordlists / databases through these helpers so that
comment/blank-line handling and packaging paths stay consistent::

    from vulnscan.core.datafiles import load_lines, load_json
    paths = load_lines("sensitive_paths.txt")
    sigs = load_json("vuln_signatures.json")
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def data_dir() -> Path:
    """Absolute path to the bundled ``vulnscan/data`` directory."""
    return _DATA_DIR


def data_path(name: str) -> Path:
    """Absolute path to a bundled data file by name."""
    return _DATA_DIR / name


def load_lines(name: str | Path) -> list[str]:
    """Load a newline wordlist, dropping blank lines and ``#`` comments.

    ``name`` may be a bare filename (resolved against the bundled data dir) or an
    absolute/relative path (used as-is), so callers can supply custom wordlists.
    """
    p = Path(name)
    if not p.is_absolute() and not p.exists():
        p = data_path(str(name))
    out: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_json(name: str | Path) -> dict[str, Any]:
    """Load a bundled (or custom-path) JSON data file."""
    p = Path(name)
    if not p.is_absolute() and not p.exists():
        p = data_path(str(name))
    return json.loads(p.read_text(encoding="utf-8"))
