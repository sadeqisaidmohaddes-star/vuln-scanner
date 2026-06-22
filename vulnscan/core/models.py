"""Core data models shared by the engine, every scanner module, and the reporters.

These types are the stable contract of the project:

* :class:`Severity`  — ordered severity levels (drives sorting and exit codes).
* :class:`Target`    — one concrete thing to scan (host, ip, domain, or url).
* :class:`Finding`   — a single structured result produced by a module.
* :class:`ScanResult`— the aggregate output of a scan (findings + metadata).

Modules should construct findings via :meth:`ScannerModule.finding` (which fills
in the module name) or by instantiating :class:`Finding` directly.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse


class Severity(enum.IntEnum):
    """Severity levels ordered from least to most severe.

    Being an :class:`enum.IntEnum`, instances compare and sort numerically, which
    the engine relies on for ranking findings and computing the process exit code.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Human-friendly title-cased name, e.g. ``Severity.HIGH.label == "High"``."""
        return self.name.capitalize()

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a severity from a case-insensitive string (``"high"`` -> ``HIGH``)."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


# Exit codes are spaced so they never collide with the conventional 0/1/2 used for
# "clean", "runtime error", and "usage error". CI gates can test e.g. `code >= 30`.
EXIT_CODES: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 20,
    Severity.HIGH: 30,
    Severity.CRITICAL: 40,
}


@dataclass
class Target:
    """A single in-scope endpoint to scan.

    The engine expands scope entries (including CIDR ranges) into concrete
    ``Target`` objects. ``kind`` is one of ``"host"``, ``"ip"``, ``"domain"`` or
    ``"url"`` and lets modules decide applicability (e.g. DNS checks run on
    ``domain`` targets; HTTP checks run on web targets).
    """

    raw: str
    host: str
    port: Optional[int] = None
    scheme: Optional[str] = None
    kind: str = "host"
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def is_web(self) -> bool:
        """Whether this target plausibly speaks HTTP(S)."""
        if self.kind == "url" or self.scheme in ("http", "https"):
            return True
        return self.port in (80, 443, 8080, 8443, 8000, 8888)

    def base_url(self, default_scheme: str = "https") -> str:
        """Best-effort base URL for HTTP modules.

        For ``url`` targets the original URL is returned. Otherwise a scheme is
        chosen from the port/scheme hints and the host (and non-default port) are
        assembled into ``scheme://host[:port]``.
        """
        if self.kind == "url" and self.raw.startswith(("http://", "https://")):
            return self.raw
        scheme = self.scheme or ("https" if self.port in (443, 8443) else default_scheme)
        netloc = self.host
        if self.port and self.port not in (80, 443):
            netloc = f"{self.host}:{self.port}"
        return f"{scheme}://{netloc}"

    @classmethod
    def from_string(cls, value: str) -> "Target":
        """Parse a target from a user string: a URL, ``host:port``, or bare host."""
        value = value.strip()
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            return cls(
                raw=value,
                host=parsed.hostname or value,
                port=parsed.port,
                scheme=parsed.scheme,
                kind="url",
            )
        # host:port (single colon, not a bracketed IPv6 literal)
        if value.count(":") == 1 and not value.startswith("["):
            host, _, port = value.partition(":")
            if port.isdigit():
                return cls(raw=value, host=host, port=int(port), kind="host")
        return cls(raw=value, host=value, kind="host")

    def __str__(self) -> str:
        if self.kind == "url":
            return self.raw
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    def __hash__(self) -> int:  # allow use in sets/dicts
        return hash((self.host, self.port, self.kind))


@dataclass
class Finding:
    """A single structured result emitted by a scanner module.

    ``id`` is a stable 12-hex-char digest of ``module|target|title`` so that the
    same issue produces the same id across runs and can be deduplicated.
    ``confidence`` is one of ``"tentative"``, ``"firm"`` or ``"confirmed"``.
    ``references`` holds CVE/CWE identifiers or advisory URLs.
    """

    title: str
    severity: Severity
    description: str
    target: str
    module: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "firm"
    id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity.from_str(self.severity)
        if not self.id:
            self.id = self._compute_id()

    def _compute_id(self) -> str:
        basis = f"{self.module}|{self.target}|{self.title}".encode("utf-8")
        return hashlib.sha1(basis).hexdigest()[:12]

    @property
    def dedupe_key(self) -> tuple[str, str, str]:
        """Key used by the engine to collapse duplicate findings."""
        return (self.module, self.target, self.title)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation (used by the JSON/HTML reporters)."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_level": int(self.severity),
            "confidence": self.confidence,
            "module": self.module,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class ScanResult:
    """Aggregate output of a completed scan."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    targets_scanned: int = 0
    modules_run: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    scope_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        """Number of findings per severity label, including zero buckets."""
        out = {sev.label: 0 for sev in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def highest(self) -> Severity:
        """The most severe finding's severity, or ``INFO`` if there are none."""
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def exit_code(self) -> int:
        """Process exit code reflecting the highest severity found (CI gating)."""
        return EXIT_CODES[self.highest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "vulnscan",
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "targets_scanned": self.targets_scanned,
            "modules_run": self.modules_run,
            "scope": self.scope_summary,
            "summary": {
                "counts": self.counts,
                "highest_severity": self.highest.label,
                "exit_code": self.exit_code(),
                "total_findings": len(self.findings),
                "errors": len(self.errors),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
