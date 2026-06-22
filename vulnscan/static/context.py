"""Repository context and configuration for static scanning.

A :class:`RepoContext` is created by :func:`vulnscan.static.repo.prepare_repo`
(which clones a remote repo or wraps a local folder) and handed to every static
module. It provides safe, bounded file access over the working tree and a shared
HTTP client (used by the dependency module to query vulnerability feeds).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Optional

if TYPE_CHECKING:
    import httpx

# Directories never worth scanning (dependencies, build output, VCS internals).
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
        "dist", "build", "out", ".next", ".nuxt", "target", ".gradle", ".mvn",
        ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".idea", ".vscode", ".terraform", ".serverless", "coverage", "htmlcov",
    }
)

# Extensions we treat as binary / non-source and skip when reading text.
BINARY_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz",
        ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".jar", ".war", ".class", ".so", ".dylib", ".dll", ".exe", ".bin",
        ".o", ".a", ".obj", ".lib", ".pyc", ".pyo", ".woff", ".woff2", ".ttf",
        ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac",
        ".db", ".sqlite", ".sqlite3", ".pdb", ".wasm",
    }
)


@dataclass
class RepoMeta:
    """Identity/provenance of the repository under analysis."""

    source: str               # original input (URL or local path)
    label: str                # short identifier, e.g. "owner/repo" or folder name
    is_remote: bool = False   # True if cloned from a remote URL
    owner: str = ""
    name: str = ""
    ref: str = ""             # resolved commit SHA or branch

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "is_remote": self.is_remote,
            "owner": self.owner,
            "name": self.name,
            "ref": self.ref,
        }


@dataclass
class StaticConfig:
    """Tunables for static scanning."""

    max_file_bytes: int = 2_000_000     # skip files larger than this when reading text
    offline: bool = False               # if True, modules must not make network calls (no OSV)
    timeout: float = 20.0               # network timeout for feed lookups
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS
    extra: dict[str, Any] = field(default_factory=dict)


class RepoContext:
    """Bounded, read-only access to a repository working tree for static modules."""

    def __init__(
        self,
        root: Path,
        meta: RepoMeta,
        config: StaticConfig,
        *,
        http_client: "Optional[httpx.AsyncClient]" = None,
        logger: Optional[logging.Logger] = None,
        cleanup_path: Optional[Path] = None,
    ) -> None:
        self.root = Path(root)
        self.meta = meta
        self.config = config
        self._http = http_client
        self.log = logger or logging.getLogger("vulnscan.static")
        self._cleanup_path = cleanup_path  # temp dir to remove on cleanup(), if any

    # -- file access -----------------------------------------------------------------

    def iter_files(
        self,
        *,
        suffixes: Optional[set[str]] = None,
        names: Optional[set[str]] = None,
    ) -> Iterator[Path]:
        """Yield files in the working tree, skipping excluded dirs and huge files.

        ``suffixes`` (lowercased, with dot) and ``names`` (exact filename) filter
        the results when provided; otherwise all non-excluded files are yielded.
        """
        suffixes = {s.lower() for s in suffixes} if suffixes else None
        names = set(names) if names else None
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Prune excluded directories in place so os.walk doesn't descend.
            dirnames[:] = [d for d in dirnames if d not in self.config.exclude_dirs]
            for fname in filenames:
                if names is not None and fname not in names:
                    if suffixes is None or Path(fname).suffix.lower() not in suffixes:
                        continue
                if suffixes is not None and names is None and Path(fname).suffix.lower() not in suffixes:
                    continue
                path = Path(dirpath) / fname
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    if path.stat().st_size > self.config.max_file_bytes:
                        continue
                except OSError:
                    continue
                yield path

    def read_text(self, path: Path) -> Optional[str]:
        """Read a file as UTF-8 text, or return None if binary/oversize/unreadable."""
        p = Path(path)
        if p.suffix.lower() in BINARY_SUFFIXES:
            return None
        try:
            if p.stat().st_size > self.config.max_file_bytes:
                return None
            raw = p.read_bytes()
        except OSError:
            return None
        if b"\x00" in raw[:8192]:  # crude binary sniff
            return None
        return raw.decode("utf-8", errors="replace")

    def rel(self, path: Path) -> str:
        """Path relative to the repo root, using forward slashes."""
        try:
            return Path(path).resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return Path(path).as_posix()

    def finding_target(self, path: Path, line: Optional[int] = None) -> str:
        """Canonical finding target string: ``<label>/<relpath>[:line]``."""
        rel = self.rel(path)
        base = f"{self.meta.label}/{rel}" if self.meta.label else rel
        return f"{base}:{line}" if line else base

    # -- shared HTTP client ----------------------------------------------------------

    @property
    def http(self) -> "httpx.AsyncClient":
        """Shared async HTTP client (for feed lookups). Raises if running offline."""
        if self._http is None:
            raise RuntimeError("No HTTP client available (offline mode).")
        return self._http

    @property
    def has_http(self) -> bool:
        return self._http is not None and not self.config.offline

    # -- lifecycle -------------------------------------------------------------------

    def cleanup(self) -> None:
        """Remove the temporary clone directory, if this context created one."""
        if self._cleanup_path is not None:
            import shutil

            shutil.rmtree(self._cleanup_path, ignore_errors=True)
            self._cleanup_path = None
