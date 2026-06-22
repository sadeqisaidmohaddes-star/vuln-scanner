"""The pluggable static-module interface.

A static module analyses a cloned repository working tree and emits the same
:class:`~vulnscan.core.models.Finding` objects as the network modules. Drop a
subclass into ``vulnscan/static/modules/`` (or a directory passed to the static
engine) and it is auto-discovered.

Example::

    from vulnscan.static import StaticModule
    from vulnscan import Severity

    class TodoFinder(StaticModule):
        name = "todo_finder"
        description = "Flags FIXME/TODO security notes."
        category = "static"
        default_severity = Severity.INFO

        async def run(self, repo):
            findings = []
            for path in repo.iter_files(suffixes={".py"}):
                text = repo.read_text(path)
                if text and "FIXME(security)" in text:
                    findings.append(self.finding(
                        title="Security FIXME left in code",
                        severity=Severity.LOW,
                        description="A security-related FIXME marker remains.",
                        target=repo.finding_target(path),
                    ))
            return findings
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

from ..core.models import Finding, Severity

if TYPE_CHECKING:
    from .context import RepoContext


class StaticModule(ABC):
    """Base class for repository (source-code) scanners.

    Class attributes mirror :class:`vulnscan.core.module_base.ScannerModule`:
    ``name``, ``description``, ``category``, ``default_severity``, and ``order``
    (lower runs earlier). Static modules are read-only and must never execute
    repository code.
    """

    name: str = "unnamed_static"
    description: str = ""
    category: str = "static"
    default_severity: Severity = Severity.INFO
    order: int = 50

    def applicable(self, repo: "RepoContext") -> bool:
        """Whether this module should run against ``repo`` (default: always)."""
        return True

    @abstractmethod
    async def run(self, repo: "RepoContext") -> list[Finding]:
        """Analyse ``repo`` and return findings (may be empty).

        Implementations MUST NOT raise on expected conditions (unreadable files,
        missing manifests, feed lookup failures): catch and degrade. The engine
        isolates unexpected exceptions, but well-behaved modules handle their own.
        """
        raise NotImplementedError

    def finding(
        self,
        *,
        title: str,
        severity: Severity,
        description: str,
        target: Any,
        evidence: Optional[dict[str, Any]] = None,
        remediation: str = "",
        references: Optional[list[str]] = None,
        confidence: str = "firm",
    ) -> Finding:
        """Construct a :class:`Finding` attributed to this module."""
        return Finding(
            title=title,
            severity=severity,
            description=description,
            target=str(target),
            module=self.name,
            evidence=evidence or {},
            remediation=remediation,
            references=references or [],
            confidence=confidence,
        )

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} name={self.name!r} order={self.order}>"
