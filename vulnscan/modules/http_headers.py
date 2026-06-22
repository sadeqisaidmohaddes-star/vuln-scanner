"""HTTP security-posture review from a single non-destructive GET request.

This module performs a passive (non-intrusive) review of an HTTP(S) endpoint's
security posture using exactly one ``GET`` request. It inspects the response
headers, cookies, and a bounded slice of the body to *detect and report*:

* missing or weak security headers (CSP, HSTS, X-Frame-Options, ...),
* software / technology disclosure via ``Server`` / ``X-Powered-By``,
* insecure cookie flags (``Secure`` / ``HttpOnly`` / ``SameSite``),
* directory-listing pages, and
* verbose error / stack-trace leakage in the response body.

It never exploits anything, never stores response bodies, and reads at most a
small bounded prefix of the body so that large or hostile responses cannot be
abused. All network egress goes through the rate-limited ``ctx.http_*`` helpers
and every expected network/parse failure degrades to an empty (or partial)
result rather than raising.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from ..core.models import Finding, Severity, Target
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

    from ..core.context import ScanContext


# Maximum number of body characters we will look at for directory-listing and
# stack-trace signatures. Keeps memory/CPU bounded on huge or hostile responses.
_BODY_SCAN_CAP = 200 * 1024

# Minimum acceptable HSTS max-age (180 days, in seconds).
_HSTS_MIN_MAX_AGE = 15552000

# Server header pattern: a product token followed by a dotted version, e.g.
# "nginx/1.18.0", "Apache/2.4.41", "Microsoft-IIS/10.0".
_SERVER_VERSION_RE = re.compile(r"([A-Za-z0-9_.\-]+)/(\d+(?:\.\d+)+)")

# HSTS max-age extraction (case-insensitive, optional surrounding whitespace).
_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)

# Stack-trace / verbose-error signatures. Each tuple is (label, substring) and is
# matched case-sensitively where the signature is conventionally cased.
_ERROR_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("python_traceback", "Traceback (most recent call last)"),
    ("java_exception", "java.lang."),
    ("php_warning", "PHP Warning"),
    ("php_fatal", "PHP Fatal error"),
    ("sql_state", "SQLSTATE"),
    ("oracle_error", "ORA-0"),
    ("dotnet_stack", "at System."),
    ("dotnet_framework", ".NET Framework"),
)


class HttpHeaders(ScannerModule):
    """Review HTTP security headers, cookies, and obvious response leakage."""

    name = "http_headers"
    description = "HTTP security-posture review from a single GET (headers, cookies, leakage)."
    category = "web"
    default_severity = Severity.LOW
    intrusive = False
    order = 20

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run only against targets that plausibly speak HTTP(S)."""
        return target.is_web

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Issue one GET and emit findings for the detected posture issues."""
        url = target.base_url()
        try:
            resp = await ctx.http_get(url)
        except Exception as exc:  # noqa: BLE001 - never raise on expected network failures
            ctx.log.debug("http_headers: GET %s failed: %s", url, exc)
            return []

        findings: list[Finding] = []
        headers = resp.headers
        is_https = self._is_https(url, target)

        findings.extend(self._check_missing_headers(target, url, headers, is_https))
        findings.extend(self._check_weak_values(target, url, headers))
        findings.extend(self._check_disclosure(target, url, headers, ctx))
        findings.extend(self._check_cookies(target, url, headers, is_https))
        findings.extend(self._check_body(target, url, resp, ctx))
        return findings

    # -- helpers ---------------------------------------------------------------------

    @staticmethod
    def _is_https(url: str, target: "Target") -> bool:
        """Best-effort determination of whether the request used HTTPS."""
        if url.startswith("https://"):
            return True
        if url.startswith("http://"):
            return False
        return target.scheme == "https" or target.port in (443, 8443)

    @staticmethod
    def _header(headers: Any, name: str) -> Optional[str]:
        """Case-insensitive single-header lookup returning ``None`` if absent.

        ``httpx.Headers`` is already case-insensitive, but this also tolerates a
        plain ``dict`` to keep the module easy to unit-test.
        """
        try:
            value = headers.get(name)
        except Exception:  # noqa: BLE001 - defensive against odd mapping types
            value = None
        if value is not None:
            return value
        lowered = name.lower()
        try:
            for key, val in headers.items():
                if key.lower() == lowered:
                    return val
        except Exception:  # noqa: BLE001
            return None
        return None

    @staticmethod
    def _get_list(headers: Any, name: str) -> list[str]:
        """Return all values for ``name`` (httpx supports repeated headers)."""
        getter = getattr(headers, "get_list", None)
        if callable(getter):
            try:
                return list(getter(name))
            except Exception:  # noqa: BLE001
                pass
        value = HttpHeaders._header(headers, name)
        return [value] if value else []

    def _check_missing_headers(
        self,
        target: "Target",
        url: str,
        headers: Any,
        is_https: bool,
    ) -> list[Finding]:
        """Flag absent recommended security headers."""
        findings: list[Finding] = []
        csp = self._header(headers, "Content-Security-Policy")
        csp_lower = (csp or "").lower()

        if not csp:
            findings.append(
                self.finding(
                    title="Missing security header: Content-Security-Policy",
                    severity=Severity.MEDIUM,
                    description=(
                        "The response does not set a Content-Security-Policy header. "
                        "CSP is a primary defence against cross-site scripting and "
                        "data-injection attacks by restricting the sources of scripts, "
                        "styles, frames, and other content."
                    ),
                    target=target,
                    evidence={"url": url, "header": "Content-Security-Policy", "present": False},
                    remediation=(
                        "Add a restrictive Content-Security-Policy header, e.g. "
                        "\"default-src 'self'; frame-ancestors 'none'; object-src 'none'\", "
                        "and tighten it iteratively for the application's needs."
                    ),
                    references=["CWE-693"],
                    confidence="firm",
                )
            )

        # HSTS is only meaningful over HTTPS; do not flag it on plain HTTP targets.
        if is_https and not self._header(headers, "Strict-Transport-Security"):
            findings.append(
                self.finding(
                    title="Missing security header: Strict-Transport-Security",
                    severity=Severity.MEDIUM,
                    description=(
                        "The HTTPS response does not set a Strict-Transport-Security "
                        "(HSTS) header. Without HSTS, browsers may be downgraded to "
                        "plaintext HTTP and are exposed to SSL-stripping attacks."
                    ),
                    target=target,
                    evidence={"url": url, "header": "Strict-Transport-Security", "present": False},
                    remediation=(
                        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                        "(consider 'preload' once verified) on all HTTPS responses."
                    ),
                    references=["CWE-693"],
                    confidence="firm",
                )
            )

        # X-Frame-Options is satisfied by a CSP 'frame-ancestors' directive.
        if not self._header(headers, "X-Frame-Options") and "frame-ancestors" not in csp_lower:
            findings.append(
                self.finding(
                    title="Missing security header: X-Frame-Options",
                    severity=Severity.LOW,
                    description=(
                        "The response sets neither an X-Frame-Options header nor a "
                        "Content-Security-Policy 'frame-ancestors' directive, leaving "
                        "the page susceptible to clickjacking via framing."
                    ),
                    target=target,
                    evidence={"url": url, "header": "X-Frame-Options", "present": False},
                    remediation=(
                        "Send 'X-Frame-Options: DENY' (or 'SAMEORIGIN'), or define a "
                        "CSP 'frame-ancestors' directive to control framing."
                    ),
                    references=["CWE-693", "CWE-1021"],
                    confidence="firm",
                )
            )

        for header_name, friendly in (
            ("X-Content-Type-Options", "X-Content-Type-Options"),
            ("Referrer-Policy", "Referrer-Policy"),
            ("Permissions-Policy", "Permissions-Policy"),
        ):
            if not self._header(headers, header_name):
                findings.append(
                    self.finding(
                        title=f"Missing security header: {friendly}",
                        severity=Severity.LOW,
                        description=(
                            f"The response does not set the {friendly} header, which "
                            "helps harden the browser against a class of attacks."
                        ),
                        target=target,
                        evidence={"url": url, "header": friendly, "present": False},
                        remediation=self._remediation_for(header_name),
                        references=["CWE-693"],
                        confidence="firm",
                    )
                )
        return findings

    @staticmethod
    def _remediation_for(header_name: str) -> str:
        """Concrete remediation text for a missing hardening header."""
        return {
            "X-Content-Type-Options": (
                "Send 'X-Content-Type-Options: nosniff' to stop browsers from "
                "MIME-sniffing responses away from the declared Content-Type."
            ),
            "Referrer-Policy": (
                "Send a privacy-preserving 'Referrer-Policy', e.g. "
                "'strict-origin-when-cross-origin' or 'no-referrer'."
            ),
            "Permissions-Policy": (
                "Send a 'Permissions-Policy' header to disable powerful browser "
                "features the application does not use (camera, microphone, geolocation, ...)."
            ),
        }.get(header_name, "Add the recommended security header to all responses.")

    def _check_weak_values(self, target: "Target", url: str, headers: Any) -> list[Finding]:
        """Flag security headers that are present but weakly configured."""
        findings: list[Finding] = []

        hsts = self._header(headers, "Strict-Transport-Security")
        if hsts:
            match = _HSTS_MAX_AGE_RE.search(hsts)
            max_age = int(match.group(1)) if match else 0
            if max_age < _HSTS_MIN_MAX_AGE:
                findings.append(
                    self.finding(
                        title="Weak HSTS policy (max-age too low)",
                        severity=Severity.LOW,
                        description=(
                            "The Strict-Transport-Security header specifies a max-age "
                            f"of {max_age} seconds, below the recommended minimum of "
                            f"{_HSTS_MIN_MAX_AGE} seconds (180 days). A short window "
                            "narrows the period during which downgrade attacks are blocked."
                        ),
                        target=target,
                        evidence={"url": url, "header": "Strict-Transport-Security",
                                  "value": hsts, "max_age": max_age},
                        remediation=(
                            "Increase HSTS max-age to at least 31536000 (1 year) and "
                            "include 'includeSubDomains'."
                        ),
                        references=["CWE-693"],
                        confidence="firm",
                    )
                )

        csp = self._header(headers, "Content-Security-Policy")
        if csp:
            csp_lower = csp.lower()
            unsafe: list[str] = []
            if "unsafe-inline" in csp_lower:
                unsafe.append("'unsafe-inline'")
            if "unsafe-eval" in csp_lower:
                unsafe.append("'unsafe-eval'")
            if self._csp_has_bare_wildcard(csp):
                unsafe.append("* (wildcard source)")
            if unsafe:
                findings.append(
                    self.finding(
                        title="Weak Content-Security-Policy (unsafe directives)",
                        severity=Severity.LOW,
                        description=(
                            "The Content-Security-Policy contains unsafe directives "
                            f"({', '.join(unsafe)}) that substantially weaken its "
                            "protection against cross-site scripting."
                        ),
                        target=target,
                        evidence={"url": url, "header": "Content-Security-Policy",
                                  "value": csp, "unsafe": unsafe},
                        remediation=(
                            "Remove 'unsafe-inline' / 'unsafe-eval' and bare '*' sources. "
                            "Use nonces or hashes for inline scripts and enumerate explicit origins."
                        ),
                        references=["CWE-693"],
                        confidence="firm",
                    )
                )

        xcto = self._header(headers, "X-Content-Type-Options")
        if xcto is not None and xcto.strip().lower() != "nosniff":
            findings.append(
                self.finding(
                    title="Weak X-Content-Type-Options value",
                    severity=Severity.LOW,
                    description=(
                        "The X-Content-Type-Options header is present but its value is "
                        f"{xcto!r} rather than 'nosniff', so browsers may still MIME-sniff "
                        "responses."
                    ),
                    target=target,
                    evidence={"url": url, "header": "X-Content-Type-Options", "value": xcto},
                    remediation="Set the header value exactly to 'nosniff'.",
                    references=["CWE-693"],
                    confidence="firm",
                )
            )
        return findings

    @staticmethod
    def _csp_has_bare_wildcard(csp: str) -> bool:
        """Return whether the CSP uses a bare '*' as a source value.

        Matches a '*' that stands alone as a directive source (e.g.
        ``default-src *``) but not host wildcards like ``*.example.com`` or the
        ``'unsafe-*'`` keyword tokens.
        """
        for directive in csp.split(";"):
            tokens = directive.strip().split()
            # tokens[0] is the directive name; the rest are sources.
            for token in tokens[1:]:
                if token == "*":
                    return True
        return False

    def _check_disclosure(
        self,
        target: "Target",
        url: str,
        headers: Any,
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Flag software/technology disclosure via Server / X-Powered-By."""
        findings: list[Finding] = []

        server = self._header(headers, "Server")
        if server:
            match = _SERVER_VERSION_RE.search(server)
            if match:
                product, version = match.group(1), match.group(2)
                try:
                    ctx.record_service(
                        host=target.host,
                        port=target.port,
                        service="http",
                        product=product,
                        version=version,
                        source=self.name,
                        raw_banner=server,
                    )
                except Exception as exc:  # noqa: BLE001 - inventory must never break the scan
                    ctx.log.debug("http_headers: record_service failed: %s", exc)
                findings.append(
                    self.finding(
                        title="Server version disclosed in response headers",
                        severity=Severity.LOW,
                        description=(
                            "The Server response header reveals the product and version "
                            f"({product} {version}). Version disclosure helps attackers "
                            "match the server against known vulnerabilities."
                        ),
                        target=target,
                        evidence={"url": url, "header": "Server", "value": server,
                                  "product": product, "version": version},
                        remediation=(
                            "Suppress or generalise the Server header (e.g. remove the "
                            "version token, or set 'server_tokens off;' on nginx / "
                            "'ServerTokens Prod' on Apache)."
                        ),
                        references=["CWE-200"],
                        confidence="firm",
                    )
                )

        powered_by = self._header(headers, "X-Powered-By")
        if powered_by:
            findings.append(
                self.finding(
                    title="Technology disclosed via X-Powered-By header",
                    severity=Severity.LOW,
                    description=(
                        "The X-Powered-By response header discloses backend technology "
                        f"({powered_by}), aiding attacker reconnaissance and "
                        "version-specific exploitation."
                    ),
                    target=target,
                    evidence={"url": url, "header": "X-Powered-By", "value": powered_by},
                    remediation=(
                        "Remove the X-Powered-By header (e.g. 'expose_php = Off' in PHP, "
                        "'app.disable(\"x-powered-by\")' in Express)."
                    ),
                    references=["CWE-200"],
                    confidence="firm",
                )
            )
        return findings

    def _check_cookies(
        self,
        target: "Target",
        url: str,
        headers: Any,
        is_https: bool,
    ) -> list[Finding]:
        """Flag cookies missing Secure / HttpOnly / SameSite protections."""
        findings: list[Finding] = []
        for raw_cookie in self._get_list(headers, "set-cookie"):
            name, flags = self._parse_cookie(raw_cookie)
            if not name:
                continue
            # Secure flag only matters / is enforceable over HTTPS.
            if is_https and "secure" not in flags:
                findings.append(
                    self.finding(
                        title=f"Insecure cookie '{name}' missing Secure flag",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Cookie '{name}' is set over HTTPS without the Secure "
                            "attribute, so it may be transmitted over plaintext HTTP "
                            "and intercepted."
                        ),
                        target=target,
                        evidence={"url": url, "cookie": name, "set_cookie": raw_cookie},
                        remediation="Add the 'Secure' attribute to the Set-Cookie header.",
                        references=["CWE-614"],
                        confidence="firm",
                    )
                )
            if "httponly" not in flags:
                findings.append(
                    self.finding(
                        title=f"Insecure cookie '{name}' missing HttpOnly flag",
                        severity=Severity.LOW,
                        description=(
                            f"Cookie '{name}' lacks the HttpOnly attribute, so it is "
                            "accessible to client-side JavaScript and can be stolen via "
                            "cross-site scripting."
                        ),
                        target=target,
                        evidence={"url": url, "cookie": name, "set_cookie": raw_cookie},
                        remediation="Add the 'HttpOnly' attribute to the Set-Cookie header.",
                        references=["CWE-1004"],
                        confidence="firm",
                    )
                )
            if "samesite" not in flags:
                findings.append(
                    self.finding(
                        title=f"Insecure cookie '{name}' missing SameSite flag",
                        severity=Severity.LOW,
                        description=(
                            f"Cookie '{name}' does not set a SameSite attribute, "
                            "weakening defence against cross-site request forgery."
                        ),
                        target=target,
                        evidence={"url": url, "cookie": name, "set_cookie": raw_cookie},
                        remediation=(
                            "Add an explicit 'SameSite' attribute ('Lax' or 'Strict', "
                            "or 'None' with 'Secure' for cross-site cookies)."
                        ),
                        references=["CWE-1275"],
                        confidence="firm",
                    )
                )
        return findings

    @staticmethod
    def _parse_cookie(raw_cookie: str) -> tuple[str, set[str]]:
        """Parse a Set-Cookie value into ``(name, {lowercased flag names})``.

        Only attribute *names* are collected (the cookie *value* is intentionally
        ignored and never stored beyond the original header echoed in evidence).
        """
        parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
        if not parts:
            return "", set()
        name = parts[0].split("=", 1)[0].strip()
        flags = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        return name, flags

    def _check_body(
        self,
        target: "Target",
        url: str,
        resp: "httpx.Response",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Scan a bounded prefix of the body for directory listings / error leaks."""
        findings: list[Finding] = []
        try:
            body = resp.text[:_BODY_SCAN_CAP]
        except Exception as exc:  # noqa: BLE001 - decoding can fail on odd encodings
            ctx.log.debug("http_headers: could not read body for %s: %s", url, exc)
            return findings

        listing_indicator = self._directory_listing_indicator(body)
        if listing_indicator is not None:
            findings.append(
                self.finding(
                    title="Directory listing enabled",
                    severity=Severity.MEDIUM,
                    description=(
                        "The response appears to be an auto-generated directory listing "
                        f"({listing_indicator!r}), exposing the names and structure of files "
                        "that may not be intended for public enumeration."
                    ),
                    target=target,
                    evidence={"url": url, "indicator": listing_indicator},
                    remediation=(
                        "Disable automatic directory indexing (e.g. 'autoindex off;' on "
                        "nginx, 'Options -Indexes' on Apache) and add an index document."
                    ),
                    references=["CWE-548"],
                    confidence="firm",
                )
            )

        snippet = self._match_error_signature(body)
        if snippet is not None:
            findings.append(
                self.finding(
                    title="Verbose error / stack trace disclosed in response body",
                    severity=Severity.MEDIUM,
                    description=(
                        "The response body contains an error or stack-trace signature, "
                        "indicating verbose error handling that can leak source paths, "
                        "framework details, or query fragments useful to an attacker."
                    ),
                    target=target,
                    evidence={"url": url, "snippet": snippet},
                    remediation=(
                        "Disable debug/verbose error output in production and return "
                        "generic error pages; log detailed errors server-side only."
                    ),
                    references=["CWE-209"],
                    confidence="firm",
                )
            )
        return findings

    @staticmethod
    def _directory_listing_indicator(body: str) -> Optional[str]:
        """Return the matched directory-listing marker, or None.

        Recognises the common auto-index shapes across servers:
        Apache/nginx ("Index of /"), Python http.server ("Directory listing for"),
        IIS, and other generic listing markers — but only when the surrounding
        body actually looks like a listing page (to avoid matching prose).
        """
        lowered = body.lower()
        markers = (
            "index of /",
            "directory listing for",
            "<title>directory listing",
            "[to parent directory]",  # IIS
        )
        matched = next((m for m in markers if m in lowered), None)
        if matched is None:
            return None
        looks_like = (
            "<title>index of" in lowered
            or "directory listing for" in lowered
            or "parent directory" in lowered
            or "[to parent directory]" in lowered
            or "<pre>" in lowered
            or "name</a>" in lowered
            or 'href="../"' in lowered
        )
        if not looks_like:
            return None
        # Report the canonical marker text rather than the lowercased match.
        return {
            "index of /": "Index of /",
            "directory listing for": "Directory listing for",
            "<title>directory listing": "Directory listing for",
            "[to parent directory]": "[To Parent Directory]",
        }[matched]

    @staticmethod
    def _match_error_signature(body: str) -> Optional[str]:
        """Return a short (<=160 char) snippet around the first error signature.

        Only the matched neighbourhood is returned; the full body is never stored.
        """
        for _label, signature in _ERROR_SIGNATURES:
            idx = body.find(signature)
            if idx != -1:
                start = max(0, idx - 20)
                snippet = body[start:idx + len(signature) + 60]
                snippet = " ".join(snippet.split())  # collapse whitespace/newlines
                return snippet[:160]
        return None
