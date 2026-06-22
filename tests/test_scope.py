"""Tests for :mod:`vulnscan.core.scope`.

Covers scope construction from a dict and from a YAML file, the in-scope safety
gate (exact host, subdomain, CIDR membership, exclusion override), target
expansion of CIDRs and parameterised URLs, default-port fallback, and the
``ScopeError`` raised when no targets are declared.
"""
from __future__ import annotations

import ipaddress

import pytest

from vulnscan.core.exceptions import ScopeError
from vulnscan.core.scope import DEFAULT_PORTS, Scope


def _scope_dict() -> dict:
    """A representative, well-formed scope mapping used across several tests."""
    return {
        "authorization": {
            "authorized": True,
            "authorized_by": "Jane Doe, CISO — Acme Corp",
            "engagement_id": "PT-2026-014",
        },
        "scope": {
            "targets": [
                "example.com",
                "192.0.2.0/28",
                "https://app.example.com/search?q=test",
            ],
            "exclude": ["192.0.2.1"],
            "ports": [80, 443],
            "nameservers": ["ns1.example.com"],
        },
        "settings": {"rate_limit": 10},
    }


# -- construction ---------------------------------------------------------------------


def test_from_dict_parses_blocks() -> None:
    scope = Scope.from_dict(_scope_dict())
    assert scope.includes == [
        "example.com",
        "192.0.2.0/28",
        "https://app.example.com/search?q=test",
    ]
    assert scope.excludes == ["192.0.2.1"]
    assert scope.ports == [80, 443]
    assert scope.nameservers == ["ns1.example.com"]
    assert scope.authorization.authorized is True
    assert scope.authorization.authorized_by == "Jane Doe, CISO — Acme Corp"


def test_from_file_reads_yaml(tmp_path) -> None:
    yaml = pytest.importorskip("yaml")
    data = _scope_dict()
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    scope = Scope.from_file(scope_path)
    assert scope.includes == data["scope"]["targets"]
    assert scope.excludes == ["192.0.2.1"]
    assert scope.ports == [80, 443]
    assert scope.authorization.engagement_id == "PT-2026-014"


def test_from_dict_missing_targets_raises() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"authorization": {"authorized": True}, "scope": {"exclude": ["x"]}})


def test_from_dict_empty_targets_raises() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"scope": {"targets": []}})


def test_from_file_missing_file_raises(tmp_path) -> None:
    with pytest.raises(ScopeError):
        Scope.from_file(tmp_path / "does-not-exist.yaml")


# -- in-scope gate --------------------------------------------------------------------


def test_in_scope_exact_host() -> None:
    scope = Scope.from_dict(_scope_dict())
    assert scope.is_in_scope("example.com") is True


def test_in_scope_subdomain() -> None:
    scope = Scope.from_dict(_scope_dict())
    # api.example.com is in scope by virtue of the example.com domain entry.
    assert scope.is_in_scope("api.example.com") is True
    # A bare-suffix collision must NOT match (notexample.com endswith "example.com"
    # only as a string, not as a dotted sub-domain).
    assert scope.is_in_scope("notexample.com") is False


def test_in_scope_ip_in_cidr() -> None:
    scope = Scope.from_dict(_scope_dict())
    # 192.0.2.5 falls inside 192.0.2.0/28 and is not excluded.
    assert ipaddress.ip_address("192.0.2.5") in ipaddress.ip_network("192.0.2.0/28")
    assert scope.is_in_scope("192.0.2.5") is True
    # Outside the /28 range.
    assert scope.is_in_scope("192.0.2.200") is False


def test_exclusion_overrides_inclusion() -> None:
    scope = Scope.from_dict(_scope_dict())
    # 192.0.2.1 is inside the included CIDR but is explicitly excluded.
    assert ipaddress.ip_address("192.0.2.1") in ipaddress.ip_network("192.0.2.0/28")
    assert scope.is_in_scope("192.0.2.1") is False


def test_in_scope_empty_host() -> None:
    scope = Scope.from_dict(_scope_dict())
    assert scope.is_in_scope("") is False
    assert scope.is_in_scope(None) is False  # type: ignore[arg-type]


# -- target expansion -----------------------------------------------------------------


def test_targets_expands_cidr_to_host_targets() -> None:
    scope = Scope.from_dict(_scope_dict())
    targets = scope.targets()

    ip_targets = [t for t in targets if t.kind == "ip"]
    hosts = {t.host for t in ip_targets}
    # A /28 has 16 addresses; net.hosts() yields the 14 usable hosts (.1 .. .14),
    # excluding the network (.0) and broadcast (.15) addresses.
    assert len(ip_targets) == 14
    assert "192.0.2.5" in hosts
    assert "192.0.2.1" in hosts  # exclusion is enforced at is_in_scope, not expansion
    assert "192.0.2.0" not in hosts
    assert "192.0.2.15" not in hosts
    # All CIDR-derived targets carry the original entry as their raw value.
    assert all(t.raw == "192.0.2.0/28" for t in ip_targets)


def test_targets_parameterized_url_is_url_kind() -> None:
    scope = Scope.from_dict(_scope_dict())
    url_targets = [t for t in scope.targets() if t.kind == "url"]
    assert len(url_targets) == 1
    url_target = url_targets[0]
    assert url_target.kind == "url"
    assert url_target.raw == "https://app.example.com/search?q=test"
    assert url_target.host == "app.example.com"


def test_targets_bare_hostname_is_domain_kind() -> None:
    scope = Scope.from_dict(_scope_dict())
    domain_targets = [t for t in scope.targets() if t.kind == "domain"]
    assert [t.host for t in domain_targets] == ["example.com"]


def test_parameterized_urls() -> None:
    scope = Scope.from_dict(_scope_dict())
    assert scope.parameterized_urls() == ["https://app.example.com/search?q=test"]


def test_parameterized_urls_excludes_plain_urls() -> None:
    data = _scope_dict()
    data["scope"]["targets"] = [
        "example.com",
        "https://app.example.com/health",  # no query string
        "https://app.example.com/search?q=test",
    ]
    scope = Scope.from_dict(data)
    assert scope.parameterized_urls() == ["https://app.example.com/search?q=test"]


# -- default ports --------------------------------------------------------------------


def test_default_ports_used_when_none_given() -> None:
    data = _scope_dict()
    del data["scope"]["ports"]
    scope = Scope.from_dict(data)
    assert scope.ports == DEFAULT_PORTS
    # It must be a distinct list, not an alias of the module-level constant.
    assert scope.ports is not DEFAULT_PORTS


def test_explicit_ports_override_defaults() -> None:
    scope = Scope.from_dict(_scope_dict())
    assert scope.ports == [80, 443]
