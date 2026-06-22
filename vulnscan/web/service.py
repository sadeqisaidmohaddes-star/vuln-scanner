"""Bridges web requests to the live (network) and static (repo) scan engines."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Optional

from ..core.context import ScanConfig
from ..core.engine import ScanEngine
from ..core.models import ScanResult
from ..core.registry import discover_modules
from ..core.scope import Scope
from ..static.context import StaticConfig
from ..static.engine import StaticEngine, discover_static_modules
from ..static.module_base import StaticModule
from ..static.repo import prepare_repo

logger = logging.getLogger("vulnscan.web.service")

ProgressFn = Callable[[dict], None]

_REPO_HINT_RE = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org)", re.IGNORECASE)
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def detect_kind(target: str) -> str:
    """Classify a target as ``"repo"`` or ``"url"``.

    Repo signals: a github/gitlab/bitbucket URL, an ``owner/repo`` shorthand, a
    ``.git`` suffix, a ``git@`` URL, or an existing local directory. Everything
    else (bare host or http(s) URL) is treated as a live URL target.
    """
    t = target.strip()
    if not t:
        return "url"
    if t.endswith(".git") or t.startswith("git@"):
        return "repo"
    if _REPO_HINT_RE.search(t):
        return "repo"
    if _OWNER_REPO_RE.match(t) and not t.startswith(("http://", "https://")):
        return "repo"
    if Path(t).expanduser().is_dir():
        return "repo"
    return "url"


def list_modules() -> dict[str, list[dict]]:
    """Return discoverable live and static modules for the UI."""
    live = [
        {"name": m.name, "description": m.description, "category": m.category, "intrusive": m.intrusive}
        for m in discover_modules()
    ]
    static = [
        {"name": m.name, "description": m.description, "category": m.category, "intrusive": False}
        for m in discover_static_modules()
    ]
    return {"live": live, "static": static}


async def run_url_scan(
    target: str,
    *,
    modules: Optional[list[str]],
    passive: bool,
    authorized: bool,
    rate_limit: float,
    concurrency: int,
    progress: ProgressFn,
) -> ScanResult:
    """Run a live network scan against a single URL/host (authorization required)."""
    scope = Scope.from_targets([target], authorized_via_cli=authorized)
    # The hard gate: refuses unless the operator attested authorization.
    scope.authorization.require(authorized)
    config = ScanConfig(rate_limit=rate_limit, concurrency=concurrency, passive=passive)
    engine = ScanEngine(scope, config, discover_modules(), log=logger)
    return await engine.run(modules, progress=progress)


async def run_repo_scan(
    source: str,
    *,
    modules: Optional[list[str]],
    token: Optional[str],
    ref: Optional[str],
    progress: ProgressFn,
) -> ScanResult:
    """Clone (or locate) a repo and run static analysis over its working tree."""
    import httpx

    config = StaticConfig()
    async with httpx.AsyncClient(
        timeout=config.timeout,
        follow_redirects=True,
        headers={"User-Agent": "vulnscan-static/0.1"},
    ) as http:
        repo = await prepare_repo(source, token=token, ref=ref, config=config, http_client=http, log=logger)
        try:
            engine = StaticEngine(config, discover_static_modules(), log=logger)
            return await engine.run(repo, modules, progress=progress)
        finally:
            repo.cleanup()
