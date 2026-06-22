"""Shared pytest configuration.

Ensures the project root is importable so ``import vulnscan`` works regardless of
how pytest is invoked. Individual test modules are otherwise self-contained.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
