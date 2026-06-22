"""Non-destructive detection of reflected-XSS and error-based SQL-injection signals.

SAFETY
------
This module performs **non-destructive detection only**. It is a
detection-and-reporting tool: it never exploits, exfiltrates, or extracts data,
never dumps a database, and never sends destructive, stacked, out-of-band (OOB),
or time-based / ``SLEEP``-style payloads. It probes only scope-provided
parameterised URLs (it does **not** crawl) and reports the *suspected* issue and
its exact location (the affected parameter) so an analyst can verify it manually.

Two conservative signals are checked per parameter, varying only the one
parameter under test while keeping every other parameter at its original value:

* **Reflected XSS** — a unique benign canary containing safe metacharacters
  (``vsx<"'>9z``) is injected and the response body is examined for the *exact*
  canary. The canary is purely a marker; it executes nothing. If the raw
  ``<`` / ``>`` / ``"`` characters are reflected un-encoded the finding is HIGH,
  otherwise (only the alphanumeric marker reflects) it is MEDIUM.
* **Error-based SQLi** — a single quote (``'``) is appended and, separately, a
  balanced control (``''``) is appended. If a known SQL-error signature appears
  for the single-quote probe but **not** for the balanced control, a suspected
  SQL-injection finding is emitted. No data is read back from the database; only
  the presence/absence of an error signature in the response is used.

All findings are reported at ``tentative`` confidence. Every network failure
(timeouts, refused connections, TLS/cert errors, DNS failures) is caught and the
affected probe is simply skipped.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core.models import Finding, Severity
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

    from ..core.context import ScanContext
    from ..core.models import Target


# Benign reflected-XSS canary. It contains the raw metacharacters that matter for
# HTML/JS injection (``<``, ``>``, ``"``, ``'``) plus a unique alphanumeric marker
# so reflections are unambiguous. It is only ever *searched for* in the response;
# it is never interpreted, rendered, or executed by this tool.
_XSS_MARKER = "vsx9z"
_XSS_CANARY = 'vsx<"\'>9z'

# Known SQL-error signatures (case-insensitive). Presence of one of these in a
# response indicates the database surfaced a syntax/quoting error — a strong
# (but still tentative) signal of error-based SQL injection. The list is taken
# from widely used detection signatures and deliberately excludes anything that
# would extract data.
_SQL_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"ORA-[0-9]{4,}",
        r"Microsoft OLE DB",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark",
        r"SQLite/JDBC",
        r"SQLSTATE",
        r"you have an error in your sql syntax",
    )
)

# Cap how much of a response body is scanned and how many parameters are probed,
# to keep request volume and memory bounded.
_MAX_PARAMS = 20
_MAX_BODY_CHARS = 200_000
_SNIPPET_CHARS = 160


class InjectionDetectModule(ScannerModule):
    """Probe parameterised URLs for reflected-XSS and error-based SQLi signals."""

    name = "injection_detect"
    description = (
        "Non-destructive detection of reflected-XSS and error-based SQLi signals "
        "on parameterised URLs"
    )
    category = "web"
    default_severity = Severity.MEDIUM
    intrusive = True
    order = 40

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run only on scope-provided parameterised URL targets.

        The module never crawls: it acts only on URL targets that already carry a
        query string (``?``) in their raw form.
        """
        return target.kind == "url" and "?" in target.raw

    # -- URL / query helpers ----------------------------------------------------------

    @staticmethod
    def _parse_params(raw: str) -> tuple[Optional[tuple], list[tuple[str, str]]]:
        """Split ``raw`` into its parsed URL parts and its ordered query pairs.

        Returns ``(parsed_url, params)`` where ``parsed_url`` is the
        :func:`urllib.parse.urlparse` result and ``params`` is the list of
        ``(name, value)`` pairs (preserving order and duplicates). Blank query
        keys are dropped. Returns ``(None, [])`` if the URL cannot be parsed.
        """
        try:
            parsed = urlparse(raw)
        except ValueError:
            return None, []
        params = [
            (name, value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if name
        ]
        return parsed, params

    @staticmethod
    def _rebuild(parsed: tuple, params: list[tuple[str, str]]) -> str:
        """Rebuild a full URL from parsed parts and a (possibly mutated) param list."""
        query = urlencode(params, doseq=False)
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment,
            )
        )

    def _mutate(
        self,
        parsed: tuple,
        params: list[tuple[str, str]],
        index: int,
        suffix: str,
    ) -> str:
        """Build a URL where only param ``index`` is varied by appending ``suffix``.

        Every other parameter keeps its original value; the targeted parameter's
        original value has ``suffix`` appended to it.
        """
        mutated = list(params)
        name, value = mutated[index]
        mutated[index] = (name, f"{value}{suffix}")
        return self._rebuild(parsed, mutated)

    # -- response fetching ------------------------------------------------------------

    async def _fetch_text(self, url: str, ctx: "ScanContext") -> Optional[str]:
        """GET ``url`` and return a bounded slice of its decoded text body.

        Returns ``None`` on any expected network failure (timeout, refused
        connection, TLS/cert error, DNS failure) — the caller skips that probe.
        The body is read only to *search* it for benign signals; nothing is
        stored or extracted beyond a short evidence snippet.
        """
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx is a project dependency
            ctx.log.debug("httpx unavailable; skipping injection probe for %s", url)
            return None

        try:
            response = await ctx.http_get(url)
        except (httpx.HTTPError, OSError) as exc:
            ctx.log.debug("injection probe failed for %s: %s", url, exc)
            return None
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug("injection probe error for %s: %s", url, exc)
            return None

        try:
            text = response.text
        except Exception as exc:  # pragma: no cover - decoding edge cases
            ctx.log.debug("could not decode body for %s: %s", url, exc)
            return None
        return text[:_MAX_BODY_CHARS]

    # -- XSS detection ----------------------------------------------------------------

    async def _check_xss(
        self,
        parsed: tuple,
        params: list[tuple[str, str]],
        index: int,
        target: "Target",
        ctx: "ScanContext",
    ) -> Optional[Finding]:
        """Inject the benign XSS canary into one parameter and check for reflection.

        Returns a finding if the canary (or at least its marker) is reflected, or
        ``None`` otherwise. The canary is never executed — only searched for.
        """
        name = params[index][0]
        url = self._mutate(parsed, params, index, _XSS_CANARY)
        body = await self._fetch_text(url, ctx)
        if body is None:
            return None

        if _XSS_CANARY in body:
            # The raw < > " ' characters survived unescaped -> high-impact reflection.
            severity = Severity.HIGH
            snippet = self._snippet(body, _XSS_CANARY)
            unescaped = True
        elif _XSS_MARKER in body:
            # Only the alphanumeric marker reflected (metacharacters were encoded
            # or stripped) -> the value is reflected but likely contextually safer.
            severity = Severity.MEDIUM
            snippet = self._snippet(body, _XSS_MARKER)
            unescaped = False
        else:
            return None

        detail = (
            "The injected metacharacters (< > \") were reflected un-encoded, "
            "which suggests the value is written into the page without contextual "
            "output encoding."
            if unescaped
            else "Only the benign marker was reflected (the metacharacters appear "
            "to be encoded or stripped); the parameter value is echoed into the "
            "response and warrants manual review of the output context."
        )
        return self.finding(
            title=f"Suspected reflected XSS in parameter '{name}'",
            severity=severity,
            description=(
                f"A unique benign canary injected into the '{name}' parameter was "
                f"reflected in the response body. {detail} This is a detection "
                f"signal only — the canary executes nothing and no exploitation "
                f"was attempted. Verify the output context (HTML, attribute, "
                f"script, etc.) manually."
            ),
            target=target,
            evidence={
                "url": url,
                "parameter": name,
                "reflected_snippet": snippet,
            },
            remediation=(
                "Apply contextual output encoding/escaping for all user-controlled "
                "values (HTML-, attribute-, JavaScript-, and URL-context aware), "
                "validate input against an allow-list, and deploy a strong "
                "Content-Security-Policy as defence in depth."
            ),
            references=["CWE-79"],
            confidence="tentative",
        )

    @staticmethod
    def _snippet(body: str, needle: str) -> str:
        """Return a short context window (<= ``_SNIPPET_CHARS``) around ``needle``."""
        idx = body.find(needle)
        if idx < 0:
            return body[:_SNIPPET_CHARS]
        pad = max(0, (_SNIPPET_CHARS - len(needle)) // 2)
        start = max(0, idx - pad)
        end = min(len(body), idx + len(needle) + pad)
        return body[start:end][:_SNIPPET_CHARS]

    # -- SQLi detection ---------------------------------------------------------------

    @staticmethod
    def _sql_error(body: str) -> Optional[str]:
        """Return the first matching SQL-error signature in ``body``, else ``None``."""
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return pattern.pattern
        return None

    async def _check_sqli(
        self,
        parsed: tuple,
        params: list[tuple[str, str]],
        index: int,
        target: "Target",
        ctx: "ScanContext",
    ) -> Optional[Finding]:
        """Compare a single-quote probe against a balanced-quote control.

        Emits a finding only when an SQL-error signature appears for the broken
        (single-quote) input but is absent from the balanced control, which
        distinguishes a genuine quoting/syntax break from a page that always
        contains the signature string. No data is extracted from the database.
        """
        name = params[index][0]

        # Broken-quote probe: append a single quote to unbalance any string literal.
        broken_url = self._mutate(parsed, params, index, "'")
        broken_body = await self._fetch_text(broken_url, ctx)
        if broken_body is None:
            return None

        signature = self._sql_error(broken_body)
        if signature is None:
            return None

        # Balanced control: append a doubled quote so the literal is re-balanced.
        # If the same error vanishes, the single quote was the cause.
        control_url = self._mutate(parsed, params, index, "''")
        control_body = await self._fetch_text(control_url, ctx)
        if control_body is None:
            # Without a control we cannot rule out an always-present signature;
            # be conservative and do not report.
            return None

        if self._sql_error(control_body) is not None:
            # The signature is present even when the quote is balanced -> it is
            # not driven by our injection. Suppress to avoid a false positive.
            return None

        return self.finding(
            title=f"Suspected SQL injection in parameter '{name}'",
            severity=Severity.HIGH,
            description=(
                f"Appending a single quote to the '{name}' parameter produced a "
                f"database error signature in the response, while a balanced "
                f"double-quote control did not — indicating the value is placed "
                f"into a SQL statement without proper parameterisation. This is a "
                f"detection signal only: no data was extracted and no destructive, "
                f"stacked, time-based, or out-of-band payloads were used."
            ),
            target=target,
            evidence={
                "url": broken_url,
                "parameter": name,
                "error_signature": signature,
            },
            remediation=(
                "Use parameterised queries / prepared statements (or a vetted ORM) "
                "for all database access, validate and canonicalise input, and "
                "ensure database error messages are not returned to clients."
            ),
            references=["CWE-89"],
            confidence="tentative",
        )

    # -- main entry point -------------------------------------------------------------

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Probe each query parameter of ``target`` for XSS and SQLi signals."""
        findings: list[Finding] = []

        parsed, params = self._parse_params(target.raw)
        if parsed is None or not params:
            return findings

        for index in range(min(len(params), _MAX_PARAMS)):
            try:
                xss = await self._check_xss(parsed, params, index, target, ctx)
                if xss is not None:
                    findings.append(xss)

                sqli = await self._check_sqli(parsed, params, index, target, ctx)
                if sqli is not None:
                    findings.append(sqli)
            except Exception as exc:  # pragma: no cover - defensive per-param guard
                # Never let one parameter's probe abort the whole module.
                name = params[index][0]
                ctx.log.debug(
                    "injection_detect probe failed for parameter %r on %s: %s",
                    name,
                    target.raw,
                    exc,
                )
                continue

        return findings
