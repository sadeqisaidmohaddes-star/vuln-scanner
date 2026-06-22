"""Tests for vulnscan.core.models.

Covers the stable data contract: Severity ordering/parsing, the EXIT_CODES
mapping, Target parsing/base_url, Finding id stability and dedupe_key, and
ScanResult aggregation plus the to_dict() serialisation shapes.
"""
from __future__ import annotations

import pytest

from vulnscan.core.models import (
    EXIT_CODES,
    Finding,
    ScanResult,
    Severity,
    Target,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_ordering():
    assert (
        Severity.CRITICAL
        > Severity.HIGH
        > Severity.MEDIUM
        > Severity.LOW
        > Severity.INFO
    )
    # Sorting (ascending) follows the numeric ordering.
    assert sorted(Severity) == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    # IntEnum members compare numerically.
    assert int(Severity.CRITICAL) == 4
    assert int(Severity.INFO) == 0
    assert max(Severity) is Severity.CRITICAL


@pytest.mark.parametrize(
    "sev",
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
)
def test_severity_from_str_round_trip(sev):
    # from_str on the label (title-cased) round-trips back to the member.
    assert Severity.from_str(sev.label) is sev
    # Round-trip via the enum name too.
    assert Severity.from_str(sev.name) is sev


def test_severity_from_str_case_and_whitespace_insensitive():
    assert Severity.from_str("high") is Severity.HIGH
    assert Severity.from_str("HIGH") is Severity.HIGH
    assert Severity.from_str("  Critical  ") is Severity.CRITICAL


def test_severity_label():
    assert Severity.HIGH.label == "High"
    assert Severity.INFO.label == "Info"
    assert str(Severity.MEDIUM) == "Medium"


def test_severity_from_str_unknown_raises():
    with pytest.raises(ValueError):
        Severity.from_str("bogus")


# ---------------------------------------------------------------------------
# EXIT_CODES
# ---------------------------------------------------------------------------


def test_exit_codes_mapping():
    assert EXIT_CODES == {
        Severity.INFO: 0,
        Severity.LOW: 10,
        Severity.MEDIUM: 20,
        Severity.HIGH: 30,
        Severity.CRITICAL: 40,
    }
    # Every severity has an exit code.
    assert set(EXIT_CODES) == set(Severity)
    # Codes increase with severity.
    ordered = [EXIT_CODES[s] for s in sorted(Severity)]
    assert ordered == sorted(ordered)


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


def test_target_from_string_url():
    t = Target.from_string("https://example.com:8443/path?q=1")
    assert t.kind == "url"
    assert t.host == "example.com"
    assert t.port == 8443
    assert t.scheme == "https"
    # url targets return the original raw URL.
    assert t.base_url() == "https://example.com:8443/path?q=1"


def test_target_from_string_host_port():
    t = Target.from_string("example.com:8080")
    assert t.kind == "host"
    assert t.host == "example.com"
    assert t.port == 8080
    assert t.scheme is None
    # No scheme/well-known-https port -> default scheme, port preserved.
    assert t.base_url() == "https://example.com:8080"


def test_target_from_string_bare_host():
    t = Target.from_string("example.com")
    assert t.kind == "host"
    assert t.host == "example.com"
    assert t.port is None
    assert t.scheme is None
    assert t.base_url() == "https://example.com"


def test_target_base_url_default_scheme_override():
    t = Target.from_string("example.com")
    assert t.base_url(default_scheme="http") == "http://example.com"


def test_target_base_url_https_port_picks_https():
    t = Target.from_string("example.com:443")
    # port 443 selects https, and 443 is omitted from the netloc.
    assert t.base_url(default_scheme="http") == "https://example.com"


def test_target_base_url_omits_default_ports():
    t80 = Target.from_string("example.com:80")
    # port 80 is a default port and dropped from the netloc; scheme falls back
    # to the default (https) since port 80 isn't an https hint.
    assert t80.base_url() == "https://example.com"
    assert ":80" not in t80.base_url()


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def _make_finding(**overrides):
    base = dict(
        title="Exposed admin panel",
        severity=Severity.HIGH,
        description="An admin panel is reachable.",
        target="example.com",
        module="http.admin",
    )
    base.update(overrides)
    return Finding(**base)


def test_finding_id_is_stable_12_char_hash():
    f = _make_finding()
    assert isinstance(f.id, str)
    assert len(f.id) == 12
    # 12 hex chars.
    int(f.id, 16)


def test_finding_id_identical_findings_share_id():
    f1 = _make_finding()
    f2 = _make_finding()
    assert f1.id == f2.id


def test_finding_id_changes_when_title_changes():
    f1 = _make_finding(title="Exposed admin panel")
    f2 = _make_finding(title="Exposed admin panel (v2)")
    assert f1.id != f2.id


def test_finding_id_changes_with_module_or_target():
    base = _make_finding()
    assert _make_finding(module="other.module").id != base.id
    assert _make_finding(target="other.host").id != base.id


def test_finding_explicit_id_is_preserved():
    f = _make_finding(id="deadbeef0000")
    assert f.id == "deadbeef0000"


def test_finding_dedupe_key():
    f = _make_finding()
    assert f.dedupe_key == ("http.admin", "example.com", "Exposed admin panel")


def test_finding_severity_string_coerced():
    f = _make_finding(severity="critical")
    assert f.severity is Severity.CRITICAL


def test_finding_to_dict_shape():
    f = _make_finding(
        severity=Severity.HIGH,
        evidence={"url": "https://example.com/admin"},
        remediation="Restrict access.",
        references=["CWE-284"],
        confidence="confirmed",
    )
    d = f.to_dict()
    assert d == {
        "id": f.id,
        "title": "Exposed admin panel",
        "severity": "High",
        "severity_level": 3,
        "confidence": "confirmed",
        "module": "http.admin",
        "target": "example.com",
        "description": "An admin panel is reachable.",
        "evidence": {"url": "https://example.com/admin"},
        "remediation": "Restrict access.",
        "references": ["CWE-284"],
    }
    # references is copied, not aliased.
    assert d["references"] is not f.references


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


def test_scan_result_counts_mixed():
    findings = [
        _make_finding(title="a", severity=Severity.CRITICAL),
        _make_finding(title="b", severity=Severity.HIGH),
        _make_finding(title="c", severity=Severity.HIGH),
        _make_finding(title="d", severity=Severity.LOW),
    ]
    result = ScanResult(findings=findings)
    assert result.counts == {
        "Critical": 1,
        "High": 2,
        "Medium": 0,
        "Low": 1,
        "Info": 0,
    }
    # All severity buckets are present, even zero ones.
    assert set(result.counts) == {"Critical", "High", "Medium", "Low", "Info"}


def test_scan_result_highest_and_exit_code_mixed():
    findings = [
        _make_finding(title="a", severity=Severity.LOW),
        _make_finding(title="b", severity=Severity.HIGH),
        _make_finding(title="c", severity=Severity.MEDIUM),
    ]
    result = ScanResult(findings=findings)
    assert result.highest is Severity.HIGH
    assert result.exit_code() == 30


def test_scan_result_empty():
    result = ScanResult()
    assert result.findings == []
    assert result.counts == {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    assert result.highest is Severity.INFO
    assert result.exit_code() == 0


def test_scan_result_to_dict_shape():
    f = _make_finding(severity=Severity.MEDIUM)
    result = ScanResult(
        findings=[f],
        errors=[{"module": "http.admin", "error": "timeout"}],
        targets_scanned=3,
        modules_run=["http.admin", "dns.basic"],
        started_at="2026-06-13T00:00:00Z",
        finished_at="2026-06-13T00:00:05Z",
        duration_seconds=5.12345,
        scope_summary={"hosts": 1},
    )
    d = result.to_dict()

    assert d["tool"] == "vulnscan"
    assert d["started_at"] == "2026-06-13T00:00:00Z"
    assert d["finished_at"] == "2026-06-13T00:00:05Z"
    # duration is rounded to 3 decimals.
    assert d["duration_seconds"] == 5.123
    assert d["targets_scanned"] == 3
    assert d["modules_run"] == ["http.admin", "dns.basic"]
    assert d["scope"] == {"hosts": 1}

    assert d["summary"] == {
        "counts": result.counts,
        "highest_severity": "Medium",
        "exit_code": 20,
        "total_findings": 1,
        "errors": 1,
    }

    assert d["findings"] == [f.to_dict()]
    assert d["errors"] == [{"module": "http.admin", "error": "timeout"}]

    # Top-level keys are exactly the documented shape.
    assert set(d) == {
        "tool",
        "started_at",
        "finished_at",
        "duration_seconds",
        "targets_scanned",
        "modules_run",
        "scope",
        "summary",
        "findings",
        "errors",
    }
