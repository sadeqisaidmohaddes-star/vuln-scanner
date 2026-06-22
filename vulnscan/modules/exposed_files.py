"""Detect reachable sensitive files and endpoints (reachability only).

This module probes a curated wordlist of sensitive paths (VCS metadata, secret
files, backups, admin panels, info endpoints, ...) against a web target and
reports **only** whether each path is reachable, access-controlled, or absent.

SAFETY
------
This is a *detection-and-reporting* tool. It NEVER downloads or stores body
contents. It issues ``HEAD`` requests and, when a server rejects ``HEAD`` (e.g.
``405 Method Not Allowed``), falls back to a single-byte ranged ``GET``
(``Range: bytes=0-0``) purely to learn the status code / headers. Evidence is
restricted to ``{url, status, content_length, content_type}`` — never any
response body. No exploitation, exfiltration, brute-forcing, or destructive
behaviour is performed.

A soft-404 baseline request is made first: if the server answers ``200`` for a
random non-existent path it is treated as a catch-all, and subsequent ``200``
responses are downgraded to ``tentative`` confidence while ``401``/``403``
signals (which are harder to fake) are preferred.
"""
from __future__ import annotations

import random
from typing import TYPE_CHECKING, Optional

from ..core.datafiles import load_lines
from ..core.models import Finding, Severity
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

    from ..core.context import ScanContext
    from ..core.models import Target


# Path-category classification keywords. Order matters: the first matching
# bucket wins, so the most sensitive (highest-severity) buckets are checked
# first. Matching is performed case-insensitively against the path.
_HIGH_KEYWORDS: tuple[str, ...] = (
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    ".env",
    ".sql",
    "backup",
    "dump",
    "db.sql",
    "db_backup",
    "id_rsa",
    ".htpasswd",
    "wp-config",
    "credentials",
    ".aws",
    "authorized_keys",
    ".ssh",
    ".npmrc",
    "appsettings",
    "settings.py",
    "local_settings",
    ".zip",
    ".tar.gz",
)

# Admin panels / info-disclosure endpoints -> MEDIUM (a present admin panel is
# notable but expected to be authenticated; reachability alone is informative).
_ADMIN_KEYWORDS: tuple[str, ...] = (
    "admin",
    "phpmyadmin",
    "pma/",
    "adminer",
    "manager/html",
    "actuator",
    "server-status",
    "server-info",
    "phpinfo",
    "info.php",
    "swagger",
    "openapi",
    "graphql",
    "metrics",
    "pprof",
    "console/",
    "wp-login",
    "wp-admin",
)

# Paths that are intentionally public and should never be reported as findings
# even when reachable (they are explicitly meant to be served).
_BENIGN_PATHS: frozenset[str] = frozenset(
    {
        "robots.txt",
        "sitemap.xml",
        ".well-known/security.txt",
    }
)


class ExposedFilesModule(ScannerModule):
    """Probe sensitive paths and report reachability without reading bodies."""

    name = "exposed_files"
    description = "Probe a wordlist of sensitive paths and report reachability only"
    category = "web"
    default_severity = Severity.MEDIUM
    intrusive = True
    order = 40

    # Cap the number of probed paths to keep total request volume reasonable.
    _MAX_PATHS = 200

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run only against targets that plausibly speak HTTP(S)."""
        return target.is_web

    # -- path classification -----------------------------------------------------------

    @staticmethod
    def _classify(path: str) -> Severity:
        """Map a sensitive path to a severity based on its category.

        VCS metadata, secret files, keys and backups are HIGH; admin panels and
        info endpoints are MEDIUM; anything else defaults to MEDIUM.
        """
        lowered = path.lower()
        for kw in _HIGH_KEYWORDS:
            if kw in lowered:
                return Severity.HIGH
        for kw in _ADMIN_KEYWORDS:
            if kw in lowered:
                return Severity.MEDIUM
        return Severity.MEDIUM

    # -- response evidence extraction (headers only, never bodies) ---------------------

    @staticmethod
    def _evidence(url: str, response: "httpx.Response") -> dict[str, object]:
        """Build the metadata-only evidence dict for a probe response.

        Only the request URL, status code, declared content length and declared
        content type are recorded. The response body is never accessed.
        """
        headers = response.headers
        content_length: Optional[str] = headers.get("content-length")
        length_value: Optional[int]
        if content_length is not None and content_length.isdigit():
            length_value = int(content_length)
        else:
            length_value = None
        return {
            "url": url,
            "status": response.status_code,
            "content_length": length_value,
            "content_type": headers.get("content-type"),
        }

    # -- probing -----------------------------------------------------------------------

    async def _probe(
        self, url: str, ctx: "ScanContext"
    ) -> Optional["httpx.Response"]:
        """Issue a HEAD probe, falling back to a single-byte ranged GET.

        Returns the response (headers only are ever inspected by callers) or
        ``None`` when the probe failed for an expected reason (timeout, refused
        connection, TLS/cert error, DNS failure). Never raises on those.
        """
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx is a project dependency
            ctx.log.debug("httpx unavailable; skipping exposed_files probe for %s", url)
            return None

        try:
            response = await ctx.http_head(url)
        except (httpx.HTTPError, OSError) as exc:
            ctx.log.debug("HEAD probe failed for %s: %s", url, exc)
            return None
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug("HEAD probe error for %s: %s", url, exc)
            return None

        # If the server rejects HEAD (405) or claims it isn't implemented (501),
        # fall back to a single-byte ranged GET. The Range header keeps the
        # transfer to one byte; we still only read status/headers, never the body.
        if response.status_code in (405, 501):
            try:
                response = await ctx.http_get(url, headers={"Range": "bytes=0-0"})
            except (httpx.HTTPError, OSError) as exc:
                ctx.log.debug("ranged-GET fallback failed for %s: %s", url, exc)
                return None
            except Exception as exc:  # pragma: no cover - defensive catch-all
                ctx.log.debug("ranged-GET fallback error for %s: %s", url, exc)
                return None

        return response

    async def _baseline_is_catch_all(self, base: str, ctx: "ScanContext") -> bool:
        """Probe a random non-existent path to detect soft-404 / catch-all 200s.

        Returns ``True`` when the server answers ``200`` for a path that should
        not exist, meaning subsequent ``200`` responses cannot be trusted as
        proof of a real resource.
        """
        nonce = random.randint(10_000_000, 99_999_999)
        url = f"{base}/vulnscan-nope-{nonce}"
        response = await self._probe(url, ctx)
        if response is None:
            # Couldn't establish a baseline; be conservative and assume the
            # server is well-behaved (200 == real resource).
            return False
        return response.status_code == 200

    # -- finding builders --------------------------------------------------------------

    def _reachable_finding(
        self,
        *,
        path: str,
        url: str,
        response: "httpx.Response",
        target: "Target",
        catch_all: bool,
    ) -> Finding:
        """Build a finding for a reachable (200) sensitive path."""
        severity = self._classify(path)
        confidence = "tentative" if catch_all else "firm"
        return self.finding(
            title=f"Sensitive path reachable: /{path}",
            severity=severity,
            description=(
                f"The path /{path} responded with HTTP 200 and appears to be "
                f"reachable without authentication. Only the status and headers "
                f"were inspected; the response body was not retrieved. "
                + (
                    "The server returned 200 for a random non-existent path, so "
                    "this result is reported with lower confidence."
                    if catch_all
                    else "Exposure of this resource may disclose source code, "
                    "secrets, configuration, or backups."
                )
            ),
            target=target,
            evidence=self._evidence(url, response),
            remediation=(
                "Remove the file from the web root or relocate it outside any "
                "served directory, or restrict access via authentication / IP "
                "allow-listing. Ensure VCS metadata, backups, dumps and secret "
                "files are never deployed to production web roots."
            ),
            references=["CWE-538", "CWE-552"],
            confidence=confidence,
        )

    def _access_controlled_finding(
        self,
        *,
        path: str,
        url: str,
        response: "httpx.Response",
        target: "Target",
    ) -> Finding:
        """Build a finding for an access-controlled (401/403) sensitive path."""
        return self.finding(
            title=f"Sensitive path present but access-controlled: /{path}",
            severity=Severity.LOW,
            description=(
                f"The path /{path} returned HTTP {response.status_code}, "
                f"indicating the resource exists but is protected by access "
                f"controls. Its presence is reported for awareness; no content "
                f"was retrieved."
            ),
            target=target,
            evidence=self._evidence(url, response),
            remediation=(
                "Confirm the access control is intentional and robust. Where "
                "possible, remove or relocate the sensitive resource entirely "
                "rather than relying solely on access control."
            ),
            references=["CWE-538", "CWE-552"],
            confidence="firm",
        )

    def _redirect_finding(
        self,
        *,
        path: str,
        url: str,
        response: "httpx.Response",
        target: "Target",
        location: str,
    ) -> Finding:
        """Build an informational finding for an on-host redirect to a path."""
        evidence = self._evidence(url, response)
        evidence["location"] = location
        return self.finding(
            title=f"Sensitive path redirects on-host: /{path}",
            severity=Severity.INFO,
            description=(
                f"The path /{path} returned HTTP {response.status_code} with an "
                f"on-host Location header, suggesting the resource exists and is "
                f"being redirected (for example to a login page). No content was "
                f"retrieved."
            ),
            target=target,
            evidence=evidence,
            remediation=(
                "Verify the redirect target is intended and that the underlying "
                "resource is not inadvertently exposed elsewhere."
            ),
            references=["CWE-538"],
            confidence="tentative",
        )

    # -- redirect helper ---------------------------------------------------------------

    @staticmethod
    def _on_host_location(response: "httpx.Response", target: "Target") -> Optional[str]:
        """Return the redirect Location if it stays on-host and isn't generic.

        Returns ``None`` for missing, off-host, or generic root/login redirects
        (which are too noisy to report).
        """
        location = response.headers.get("location")
        if not location:
            return None
        loc = location.strip()
        if not loc:
            return None

        from urllib.parse import urlparse

        parsed = urlparse(loc)
        # Off-host absolute redirect -> skip.
        if parsed.netloc and target.host and parsed.hostname != target.host:
            return None
        # Generic redirect to site root -> too noisy, skip.
        path_only = parsed.path or loc
        if path_only in ("", "/"):
            return None
        return loc

    # -- main entry point --------------------------------------------------------------

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Probe sensitive paths against ``target`` and return reachability findings."""
        findings: list[Finding] = []

        base = target.base_url().rstrip("/")

        try:
            paths = load_lines("sensitive_paths.txt")
        except (OSError, ValueError) as exc:
            ctx.log.debug("could not load sensitive_paths.txt: %s", exc)
            return findings

        if not paths:
            return findings

        # Establish the soft-404 baseline before probing real paths.
        catch_all = await self._baseline_is_catch_all(base, ctx)
        if catch_all:
            ctx.log.debug(
                "%s appears to return 200 for non-existent paths; "
                "downgrading 200 results to tentative",
                base,
            )

        for raw_path in paths[: self._MAX_PATHS]:
            path = raw_path.lstrip("/")
            if not path:
                continue
            if path in _BENIGN_PATHS:
                continue

            url = f"{base}/{path}"
            response = await self._probe(url, ctx)
            if response is None:
                continue

            status = response.status_code

            if status == 200:
                # Under a catch-all server every path is 200; only report when we
                # have a real signal (no catch-all) to avoid flooding tentative
                # noise. Still emit, but flagged tentative, per the contract.
                findings.append(
                    self._reachable_finding(
                        path=path,
                        url=url,
                        response=response,
                        target=target,
                        catch_all=catch_all,
                    )
                )
            elif status in (401, 403):
                findings.append(
                    self._access_controlled_finding(
                        path=path,
                        url=url,
                        response=response,
                        target=target,
                    )
                )
            elif status in (301, 302, 307, 308):
                location = self._on_host_location(response, target)
                if location is not None:
                    findings.append(
                        self._redirect_finding(
                            path=path,
                            url=url,
                            response=response,
                            target=target,
                            location=location,
                        )
                    )
            # All other statuses (404, 410, 5xx, ...) are treated as "not
            # reachable / not present" and produce no finding.

        return findings
