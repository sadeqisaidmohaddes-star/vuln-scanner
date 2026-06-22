"""Acquire a repository working tree for static analysis.

:func:`prepare_repo` accepts a GitHub URL, an ``owner/repo`` shorthand, a generic
git URL, or a local directory path. Remote repos are **shallow-cloned** into an
isolated temporary directory. We only ever *read* the resulting files — no build,
install, or repository hook is executed.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .context import RepoContext, RepoMeta, StaticConfig

logger = logging.getLogger("vulnscan.static.repo")

_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class RepoError(Exception):
    """Raised when a repository cannot be acquired."""


def parse_source(source: str) -> tuple[str, RepoMeta]:
    """Return ``(clone_url_or_path, RepoMeta)`` for a user-supplied source.

    Supported forms:
      * local existing path (used in place, not cloned)
      * ``owner/repo``                      -> https://github.com/owner/repo.git
      * ``https://github.com/owner/repo``   (optionally with .git / trailing path)
      * ``git@github.com:owner/repo.git``
      * any other ``http(s)://`` or ``git://`` URL (cloned as-is)
    """
    source = source.strip()
    if not source:
        raise RepoError("Empty repository source.")

    # Local path?
    p = Path(source)
    if p.exists() and p.is_dir():
        return str(p), RepoMeta(source=source, label=p.resolve().name, is_remote=False)

    owner = name = ""
    # owner/repo shorthand
    if _OWNER_REPO_RE.match(source):
        owner, name = source.split("/", 1)
        name = name[:-4] if name.endswith(".git") else name
        return f"https://github.com/{owner}/{name}.git", RepoMeta(
            source=source, label=f"{owner}/{name}", is_remote=True, owner=owner, name=name
        )

    # scp-like git URL: git@github.com:owner/repo.git
    scp = re.match(r"^git@([^:]+):([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$", source)
    if scp:
        owner, name = scp.group(2), scp.group(3)
        return source, RepoMeta(source=source, label=f"{owner}/{name}", is_remote=True, owner=owner, name=name)

    # http(s)/git URL
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https", "git", "ssh"):
        parts = [seg for seg in parsed.path.split("/") if seg]
        if len(parts) >= 2:
            owner = parts[0]
            name = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
        label = f"{owner}/{name}" if owner and name else (parsed.netloc + parsed.path)
        url = source if source.endswith(".git") else source.rstrip("/")
        if "github.com" in parsed.netloc and not url.endswith(".git") and owner and name:
            url = f"{parsed.scheme}://{parsed.netloc}/{owner}/{name}.git"
        return url, RepoMeta(source=source, label=label, is_remote=True, owner=owner, name=name)

    raise RepoError(f"Unrecognised repository source: {source!r}")


def _authenticated_url(url: str, token: Optional[str]) -> str:
    """Inject a token into an https github URL for private-repo access."""
    if not token:
        return url
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.username is None:
        return f"https://x-access-token:{token}@{parsed.netloc}{parsed.path}"
    return url


async def _run_git(args: list[str], *, timeout: float, cwd: Optional[str] = None) -> tuple[int, str]:
    """Run a git command with prompts disabled; return (returncode, combined output)."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"   # never block waiting for credentials
    env["GIT_ASKPASS"] = "echo"
    env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", *args,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        raise RepoError("git is not installed or not on PATH.") from exc
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        raise RepoError(f"git {args[0]} timed out after {timeout}s.") from exc
    return proc.returncode or 0, (out or b"").decode("utf-8", errors="replace")


async def prepare_repo(
    source: str,
    *,
    token: Optional[str] = None,
    ref: Optional[str] = None,
    config: Optional[StaticConfig] = None,
    http_client=None,
    clone_timeout: float = 120.0,
    log: Optional[logging.Logger] = None,
) -> RepoContext:
    """Clone (or locate) ``source`` and return a ready :class:`RepoContext`.

    The caller owns the returned context and MUST call ``ctx.cleanup()`` when done
    (it removes the temporary clone for remote sources; local folders are left
    untouched).
    """
    log = log or logger
    config = config or StaticConfig()
    clone_url, meta = parse_source(source)

    # Local directory: wrap in place, no clone, no cleanup.
    if not meta.is_remote:
        root = Path(clone_url)
        return RepoContext(root, meta, config, http_client=http_client, logger=log)

    tmp = Path(tempfile.mkdtemp(prefix="vulnscan_repo_"))
    dest = tmp / "repo"
    args = ["clone", "--depth", "1", "--single-branch"]
    if ref:
        args += ["--branch", ref]
    args += [_authenticated_url(clone_url, token), str(dest)]
    log.info("Cloning %s", meta.label)
    code, output = await _run_git(args, timeout=clone_timeout)
    if code != 0 or not dest.exists():
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)
        # Redact any token that may appear in echoed URLs.
        safe = output.replace(token, "***") if token else output
        raise RepoError(f"git clone failed for {meta.label}: {safe.strip()[-400:]}")

    # Resolve the checked-out commit for provenance (best effort).
    rc, head = await _run_git(["rev-parse", "HEAD"], timeout=15, cwd=str(dest))
    if rc == 0:
        meta.ref = head.strip()

    return RepoContext(dest, meta, config, http_client=http_client, logger=log, cleanup_path=tmp)
