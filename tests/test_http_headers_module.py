"""End-to-end tests for the ``http_headers`` scanner module.

These tests drive the real :class:`~vulnscan.modules.http_headers.HttpHeaders`
module against fully controlled HTTP responses using ``httpx.MockTransport`` so
*no* network traffic is generated. A single GET is issued by the module; the
mock transport answers it with a crafted response and we assert on the resulting
findings and on the side effects recorded into the shared inventory.
"""
from __future__ import annotations

import httpx
import pytest

from vulnscan.core.context import ScanConfig, ScanContext
from vulnscan.core.models import Target
from vulnscan.core.ratelimit import RateLimiter
from vulnscan.core.scope import Scope
from vulnscan.modules.http_headers import HttpHeaders


# --- fixtures / helpers ------------------------------------------------------


def _make_scope() -> Scope:
    """A minimal in-scope, authorized scope targeting ``example.com``."""
    return Scope.from_dict(
        {
            "authorization": {
                "authorized": True,
                "authorized_by": "Test Harness",
                "engagement_id": "TEST-0001",
            },
            "scope": {"targets": ["example.com"]},
        }
    )


def make_context(handler) -> ScanContext:
    """Build a :class:`ScanContext` whose ``.http`` client is fully mocked.

    ``handler`` is a callable ``httpx.Request -> httpx.Response`` installed as the
    transport, so every request the module makes is answered locally without any
    socket being opened.
    """
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    config = ScanConfig()
    limiter = RateLimiter(config.rate_limit, config.concurrency)
    return ScanContext(
        config=config,
        scope=_make_scope(),
        http_client=client,
        limiter=limiter,
    )


def _target() -> Target:
    """A web target whose base URL is ``https://example.com``."""
    target = Target.from_string("https://example.com")
    # Sanity: the module issues a GET to exactly this URL.
    assert target.base_url() == "https://example.com"
    assert target.host == "example.com"
    assert target.is_web
    return target


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _has_title_substring(findings, *needles: str) -> bool:
    """True if some finding's title contains *all* of the given substrings."""
    for f in findings:
        if all(n in f.title for n in needles):
            return True
    return False


# --- case 1: an insecure response yields the expected findings ---------------


def _insecure_handler(request: httpx.Request) -> httpx.Response:
    """A weak 200 response: missing CSP/HSTS, leaky Server, insecure cookie,
    directory-listing body, and an embedded Python stack trace."""
    body = (
        "<html><head><title>Index of /</title></head><body>"
        "<h1>Index of /</h1><pre>"
        '<a href="../">Parent Directory</a>\n'
        '<a href="secret.txt">secret.txt</a>\n'
        "</pre>"
        "<div>Traceback (most recent call last):\n"
        '  File "/app/server.py", line 42, in handler\n'
        "    raise ValueError('boom')\n"
        "ValueError: boom</div>"
        "</body></html>"
    )
    # httpx accepts repeated headers as a list of (name, value) tuples; we only
    # need a single Set-Cookie here.
    headers = [
        ("Server", "nginx/1.18.0"),
        ("Set-Cookie", "SID=abc; Path=/"),
        ("Content-Type", "text/html; charset=utf-8"),
    ]
    return httpx.Response(200, headers=headers, text=body)


@pytest.mark.asyncio
async def test_insecure_response_emits_expected_findings():
    ctx = make_context(_insecure_handler)
    try:
        module = HttpHeaders()
        target = _target()

        findings = await module.run(target, ctx)

        titles = _titles(findings)
        # Missing security headers.
        assert _has_title_substring(findings, "Content-Security-Policy"), titles
        assert _has_title_substring(findings, "Strict-Transport-Security"), titles
        # Software disclosure.
        assert _has_title_substring(findings, "Server version disclosed"), titles
        # Insecure cookie missing the Secure flag (title contains both phrases).
        assert _has_title_substring(findings, "Insecure cookie", "Secure"), titles
        # Body-based issues.
        assert _has_title_substring(findings, "Directory listing enabled"), titles
        assert _has_title_substring(findings, "Verbose error"), titles
    finally:
        await ctx.http.aclose()


@pytest.mark.asyncio
async def test_insecure_response_records_nginx_service_in_inventory():
    ctx = make_context(_insecure_handler)
    try:
        module = HttpHeaders()
        target = _target()

        await module.run(target, ctx)

        services = ctx.inventory.for_host("example.com")
        assert services, "expected an inventory observation for example.com"
        nginx = [s for s in services if s.product == "nginx"]
        assert len(nginx) == 1, [s.to_dict() for s in services]
        obs = nginx[0]
        assert obs.product == "nginx"
        assert obs.version == "1.18.0"
        assert obs.host == "example.com"
        assert obs.raw_banner == "nginx/1.18.0"
    finally:
        await ctx.http.aclose()


# --- case 2: a hardened response yields no missing-header findings ------------


def _hardened_handler(request: httpx.Request) -> httpx.Response:
    """A fully hardened 200 response: all recommended headers present, a secure
    cookie, and a clean body with no listing/stack-trace signatures."""
    headers = [
        (
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
        ),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
        # No Server / X-Powered-By disclosure, secure session cookie.
        ("Set-Cookie", "SID=abc; Path=/; Secure; HttpOnly; SameSite=Strict"),
        ("Content-Type", "text/html; charset=utf-8"),
    ]
    body = "<html><head><title>Welcome</title></head><body><p>Hello.</p></body></html>"
    return httpx.Response(200, headers=headers, text=body)


@pytest.mark.asyncio
async def test_hardened_response_has_no_missing_header_findings():
    ctx = make_context(_hardened_handler)
    try:
        module = HttpHeaders()
        target = _target()

        findings = await module.run(target, ctx)

        # No "Missing security header: ..." findings of any kind.
        missing = [f for f in findings if f.title.startswith("Missing security header")]
        assert missing == [], _titles(findings)

        # And none of the specific posture issues from the insecure case.
        assert not _has_title_substring(findings, "Content-Security-Policy"), _titles(findings)
        assert not _has_title_substring(findings, "Strict-Transport-Security"), _titles(findings)
        assert not _has_title_substring(findings, "Server version disclosed"), _titles(findings)
        assert not _has_title_substring(findings, "Insecure cookie"), _titles(findings)
        assert not _has_title_substring(findings, "Directory listing enabled"), _titles(findings)
        assert not _has_title_substring(findings, "Verbose error"), _titles(findings)
    finally:
        await ctx.http.aclose()
