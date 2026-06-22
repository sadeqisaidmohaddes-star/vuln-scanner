"""Bounded default-credential CHECK against HTTP Basic authentication surfaces.

This module performs a small, rate-limited default-credential CHECK and takes
**no** post-authentication action whatsoever.

SAFETY
------
This is a *detection-and-reporting* tool only. It does the following and nothing
more:

* Detects an HTTP Basic authentication surface by issuing a single ``GET`` and
  inspecting the ``401`` status / ``WWW-Authenticate: Basic`` header (a couple of
  common admin paths are optionally probed the same way).
* For each well-known default credential (loaded from ``default_creds.json`` and
  restricted to ``service == "http-basic"`` entries — form logins are out of
  scope), it makes **at most one** authenticated ``GET`` attempt per surface and
  observes only the status code.
* As soon as one credential is accepted on a surface, it records the finding and
  **stops** testing that surface.

It is NOT a brute-forcer: each credential is tried exactly once, the list is
capped, and there is no session reuse, no navigation, no enumeration, no reading
or storing of response bodies, and no other action after a successful
authentication. All network I/O goes through the rate-limited context helpers,
and every expected network failure is caught and skipped.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlsplit

from ..core.datafiles import load_json
from ..core.models import Finding, Severity
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

    from ..core.context import ScanContext
    from ..core.models import Target


# Common admin/console paths additionally probed for a Basic-auth surface. These
# are kept deliberately short to limit request volume; they are well-known
# administrative endpoints that frequently sit behind HTTP Basic auth.
_ADMIN_PATHS: tuple[str, ...] = (
    "/admin",
    "/manager/html",
)

# Substrings that mark a URL path as an administrative / management console, in
# which case accepted default credentials are escalated to CRITICAL.
_ADMIN_PATH_MARKERS: tuple[str, ...] = (
    "admin",
    "manager",
    "console",
    "management",
)

# Statuses that indicate the credential was rejected (so we keep trying).
_REJECTED_STATUSES: frozenset[int] = frozenset({401, 403})


class DefaultCredsModule(ScannerModule):
    """Check a small list of default credentials against HTTP Basic surfaces."""

    name = "default_creds"
    description = "Check well-known default credentials against HTTP Basic auth surfaces"
    category = "auth"
    default_severity = Severity.HIGH
    intrusive = True
    order = 40

    # Hard cap on the number of credentials attempted per surface, defence in
    # depth against an over-large data file turning this into a brute-forcer.
    _MAX_CREDS = 25

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run only against targets that plausibly speak HTTP(S)."""
        return target.is_web

    # -- Basic-auth surface detection --------------------------------------------------

    @staticmethod
    def _is_basic_surface(response: "httpx.Response") -> bool:
        """Return whether ``response`` advertises an HTTP Basic auth challenge.

        A surface qualifies when the status is ``401`` and the
        ``WWW-Authenticate`` header begins (case-insensitively) with ``Basic``.
        """
        if response.status_code != 401:
            return False
        header = response.headers.get("www-authenticate", "")
        return header.strip().lower().startswith("basic")

    async def _detect_surface(
        self, url: str, ctx: "ScanContext"
    ) -> bool:
        """Probe ``url`` once and report whether it is a Basic-auth surface.

        Returns ``False`` (never raises) on any expected network failure
        (timeout, connection refused, TLS/cert error, DNS failure).
        """
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx is a project dependency
            ctx.log.debug("httpx unavailable; skipping default_creds for %s", url)
            return False

        try:
            response = await ctx.http_get(url)
        except (httpx.HTTPError, OSError) as exc:
            ctx.log.debug("basic-auth surface probe failed for %s: %s", url, exc)
            return False
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug("basic-auth surface probe error for %s: %s", url, exc)
            return False

        return self._is_basic_surface(response)

    # -- credential checking -----------------------------------------------------------

    @staticmethod
    def _looks_like_admin(url: str) -> bool:
        """Return whether the URL path looks like an admin / management console."""
        path = urlsplit(url).path.lower()
        return any(marker in path for marker in _ADMIN_PATH_MARKERS)

    def _load_basic_creds(self, ctx: "ScanContext") -> list[dict[str, Any]]:
        """Load and filter ``http-basic`` credential entries from the data file.

        Returns an empty list (never raises) when the file is missing or
        malformed. The result is capped to ``_MAX_CREDS`` entries.
        """
        try:
            data = load_json("default_creds.json")
        except (OSError, ValueError) as exc:
            ctx.log.debug("could not load default_creds.json: %s", exc)
            return []

        raw = data.get("credentials", []) if isinstance(data, dict) else []
        creds: list[dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            if entry.get("service") != "http-basic":
                continue
            username = entry.get("username")
            password = entry.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                continue
            creds.append({"username": username, "password": password})
        return creds[: self._MAX_CREDS]

    async def _try_credential(
        self,
        url: str,
        username: str,
        password: str,
        ctx: "ScanContext",
    ) -> Optional[int]:
        """Attempt one Basic-auth ``GET`` and return the status code.

        Returns ``None`` (never raises) on any expected network failure. Only the
        status code is observed; the response body is never read or stored.
        """
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx is a project dependency
            return None

        try:
            response = await ctx.http_get(
                url, auth=httpx.BasicAuth(username, password)
            )
        except (httpx.HTTPError, OSError) as exc:
            ctx.log.debug(
                "credential attempt failed for %s as %r: %s", url, username, exc
            )
            return None
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug(
                "credential attempt error for %s as %r: %s", url, username, exc
            )
            return None

        return response.status_code

    def _accepted_finding(
        self,
        *,
        url: str,
        username: str,
        password: str,
        status: int,
        target: "Target",
    ) -> Finding:
        """Build the finding for an accepted default credential."""
        is_admin = self._looks_like_admin(url)
        severity = Severity.CRITICAL if is_admin else Severity.HIGH
        return self.finding(
            title=f"Default credentials accepted: {username}:{password}",
            severity=severity,
            description=(
                f"The HTTP Basic authentication surface at {url} accepted the "
                f"well-known default credential {username!r}:{password!r} "
                f"(HTTP {status}). "
                + (
                    "The path resembles an administrative / management console, "
                    "so a foothold here is likely to grant privileged access. "
                    if is_admin
                    else ""
                )
                + "Only the authentication status was observed; no further action "
                "was taken and no response content was retrieved."
            ),
            target=target,
            evidence={
                "url": url,
                "username": username,
                "password": password,
                "status": status,
            },
            remediation=(
                "Change or disable the default credentials immediately and "
                "enforce strong, unique authentication (ideally combined with a "
                "rate-limited / locked-out login surface and, where possible, "
                "multi-factor authentication)."
            ),
            references=["CWE-1392", "CWE-798"],
            confidence="firm",
        )

    async def _check_surface(
        self, url: str, creds: list[dict[str, Any]], target: "Target", ctx: "ScanContext"
    ) -> Optional[Finding]:
        """Try each credential against one surface, stopping at the first hit.

        Returns a single finding when a credential is accepted, otherwise
        ``None``. At most one attempt is made per credential and testing of the
        surface stops as soon as one is accepted.
        """
        for cred in creds:
            username = cred["username"]
            password = cred["password"]
            status = await self._try_credential(url, username, password, ctx)
            if status is None:
                continue
            if status in _REJECTED_STATUSES:
                continue
            # Any non-401/403 response (e.g. 200) means the surface let us in.
            return self._accepted_finding(
                url=url,
                username=username,
                password=password,
                status=status,
                target=target,
            )
        return None

    # -- main entry point --------------------------------------------------------------

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Detect Basic-auth surfaces and report any accepted default credentials."""
        findings: list[Finding] = []

        base = target.base_url().rstrip("/")

        # Candidate surfaces: the base URL plus a couple of common admin paths.
        # Deduplicate while preserving order so each surface is probed once.
        candidates: list[str] = []
        for candidate in (base, *(f"{base}{path}" for path in _ADMIN_PATHS)):
            if candidate not in candidates:
                candidates.append(candidate)

        surfaces: list[str] = []
        for url in candidates:
            if await self._detect_surface(url, ctx):
                surfaces.append(url)

        if not surfaces:
            return findings

        creds = self._load_basic_creds(ctx)
        if not creds:
            return findings

        for url in surfaces:
            finding = await self._check_surface(url, creds, target, ctx)
            if finding is not None:
                findings.append(finding)
            # Move on to the next surface; nothing further is done with an
            # accepted credential beyond reporting it.

        return findings
