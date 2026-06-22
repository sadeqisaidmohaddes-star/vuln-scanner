"""Static analysis of source repositories (GitHub repos or local folders).

Unlike the network scanner in :mod:`vulnscan.modules`, these modules operate on a
*cloned working tree* — they read files, never execute repository code. They
reuse the same :class:`~vulnscan.core.models.Finding` / ``Severity`` / ``ScanResult``
model and reporting, so the web UI can present live and static results uniformly.
"""
from __future__ import annotations

from .context import RepoContext, RepoMeta, StaticConfig
from .engine import StaticEngine
from .module_base import StaticModule

__all__ = ["RepoContext", "RepoMeta", "StaticConfig", "StaticEngine", "StaticModule"]
