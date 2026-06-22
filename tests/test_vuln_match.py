"""Tests for the vuln_match correlation module.

Exercises the version comparator's boundary behaviour and the
inventory -> signature -> finding correlation path, with no network I/O.
"""
from __future__ import annotations

import httpx
import pytest

from vulnscan.core.context import ScanConfig, ScanContext
from vulnscan.core.models import Target
from vulnscan.core.ratelimit import RateLimiter
from vulnscan.core.registry import discover_modules
from vulnscan.core.scope import Scope


def _module():
    return next(m for m in discover_modules() if m.name == "vuln_match")


def _scope() -> Scope:
    return Scope.from_dict(
        {
            "authorization": {"authorized": True, "authorized_by": "Test"},
            "scope": {"targets": ["10.0.0.9"]},
        }
    )


async def _run(observations: list[tuple[str, int, str, str, str]]):
    module = _module()
    async with httpx.AsyncClient() as http:
        ctx = ScanContext(ScanConfig(), _scope(), http, RateLimiter(50, 10))
        for host, port, service, product, version in observations:
            ctx.record_service(
                host=host, port=port, service=service, product=product, version=version, source="test"
            )
        target = Target(raw="10.0.0.9", host="10.0.0.9", kind="ip")
        return await module.run(target, ctx)


def _cves(findings) -> set[str]:
    return {ref for f in findings for ref in f.references if ref.startswith("CVE")}


@pytest.mark.parametrize(
    "obs, expect_hit, expect_cve",
    [
        (("10.0.0.9", 22, "ssh", "OpenSSH", "9.0"), True, "CVE-2023-38408"),   # in [8.5, 9.3p2)
        (("10.0.0.9", 22, "ssh", "OpenSSH", "9.4"), False, None),              # >= fixed
        (("10.0.0.9", 80, "http", "nginx", "1.18.0"), True, "CVE-2021-23017"), # < 1.21.0
        (("10.0.0.9", 80, "http", "nginx", "1.21.0"), False, None),            # fixed boundary
        (("10.0.0.9", 80, "http", "Apache", "2.4.49"), True, "CVE-2021-42013"),# exact-version list
        (("10.0.0.9", 80, "http", "Apache", "2.4.51"), False, None),           # patched
        (("10.0.0.9", 21, "ftp", "vsftpd", "2.3.4"), True, "CVE-2011-2523"),   # exact backdoor
    ],
)
async def test_version_boundaries(obs, expect_hit, expect_cve) -> None:
    findings = await _run([obs])
    assert bool(findings) is expect_hit
    if expect_cve is not None:
        assert expect_cve in _cves(findings)


async def test_no_match_without_version() -> None:
    # An observation lacking a version cannot be matched.
    findings = await _run([("10.0.0.9", 22, "ssh", "OpenSSH", "")])
    assert findings == []


async def test_empty_inventory_returns_no_findings() -> None:
    findings = await _run([])
    assert findings == []


async def test_severity_comes_from_signature() -> None:
    findings = await _run([("10.0.0.9", 21, "ftp", "vsftpd", "2.3.4")])
    assert findings
    assert findings[0].severity.label == "Critical"
