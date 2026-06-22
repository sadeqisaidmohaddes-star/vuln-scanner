"""The pluggable scanner-module interface.

Every scanner — built-in or user plugin — subclasses :class:`ScannerModule` and
implements :meth:`run`. The engine discovers subclasses automatically, so simply
dropping a module file into ``vulnscan/modules/`` or ``vulnscan/plugins/`` (or a
directory passed via ``--plugins-dir``) registers it.

Minimal example::

    from vulnscan import ScannerModule, Severity

    class MyCheck(ScannerModule):
        name = "my_check"
        description = "Example custom check"
        category = "web"
        default_severity = Severity.LOW
        intrusive = False          # skipped under --passive when True

        def applicable(self, target, ctx):
            return target.is_web

        async def run(self, target, ctx):
            findings = []
            # ... inspect target using ctx.http_get(...) etc. ...
            return findings
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

from .models import Finding, Severity, Target

if TYPE_CHECKING:
    from .context import ScanContext


class ScannerModule(ABC):
    """Base class implementing the common module contract.

    Class attributes
    ----------------
    name:
        Unique, stable, machine-friendly identifier (used by ``--modules`` and as
        ``Finding.module``). Subclasses MUST set this.
    description:
        One-line human description (shown by ``--list-modules``).
    category:
        Grouping label, e.g. ``"network"``, ``"web"``, ``"tls"``, ``"dns"``.
    default_severity:
        Typical severity for this module's findings (informational metadata).
    intrusive:
        If ``True`` the module performs active probing and is skipped in
        ``--passive`` mode.
    order:
        Execution tier. Lower runs earlier. Discovery modules use the default
        (50); correlation modules that consume the shared inventory (e.g.
        ``vuln_match``) use a higher value so they run after discovery completes.
    """

    name: str = "unnamed"
    description: str = ""
    category: str = "general"
    default_severity: Severity = Severity.INFO
    intrusive: bool = False
    order: int = 50

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Return whether this module should run against ``target``.

        Default: always applicable. Override to restrict (e.g. only web targets).
        """
        return True

    @abstractmethod
    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Scan ``target`` and return a list of :class:`Finding` (may be empty).

        Implementations MUST NOT raise on expected failure conditions (timeouts,
        connection refused, TLS errors): catch those and either return ``[]`` or
        an informational finding. The engine guards against unexpected exceptions,
        but well-behaved modules degrade gracefully on their own.
        """
        raise NotImplementedError

    # -- helper for building findings with the module name pre-filled ----------------

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
