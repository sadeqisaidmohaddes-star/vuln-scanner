"""Scope definition, parsing, and in-scope enforcement.

The :class:`Scope` is the second safety control (after authorization): the engine
checks :meth:`Scope.is_in_scope` before any module touches a host, so out-of-scope
systems are never probed even if a module or wordlist references them.

Scope file format (YAML or JSON)::

    authorization:
      authorized: true
      authorized_by: "Jane Doe, CISO — Acme Corp"
      engagement_id: "PT-2026-014"
      date: "2026-06-13"
      expires: "2026-07-13"
    scope:
      targets:
        - example.com
        - 192.0.2.0/28
        - https://app.example.com/search?q=test   # parameterised URL for injection checks
      exclude:
        - 192.0.2.1
      ports: [21, 22, 25, 80, 443, 3306, 8080, 8443]
      nameservers:
        - ns1.example.com
    settings:
      rate_limit: 10
      concurrency: 20
      timeout: 10
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from .authorization import Authorization
from .exceptions import ScopeError
from .models import Target

# Default ports scanned when a scope file does not specify any.
DEFAULT_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                            1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]

# Safety cap on CIDR expansion so a stray /8 cannot fan out into millions of hosts.
MAX_CIDR_HOSTS = 4096


class Scope:
    """Resolved scope: authorization, in-scope targets, exclusions, and settings."""

    def __init__(
        self,
        *,
        authorization: Authorization,
        includes: list[str],
        excludes: list[str],
        ports: list[int],
        nameservers: list[str],
        settings: dict[str, Any],
        raw: Optional[dict[str, Any]] = None,
    ) -> None:
        self.authorization = authorization
        self.includes = includes
        self.excludes = excludes
        self.ports = ports or list(DEFAULT_PORTS)
        self.nameservers = nameservers
        self.settings = settings or {}
        self.raw = raw or {}

        # Pre-parse include/exclude entries into fast lookup structures.
        self._inc_networks: list[ipaddress._BaseNetwork] = []
        self._inc_hosts: set[str] = set()
        self._inc_domains: set[str] = set()
        self._exc_networks: list[ipaddress._BaseNetwork] = []
        self._exc_hosts: set[str] = set()
        self._exc_domains: set[str] = set()
        self._index(includes, self._inc_networks, self._inc_hosts, self._inc_domains)
        self._index(excludes, self._exc_networks, self._exc_hosts, self._exc_domains)

    # -- construction ----------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """Load a scope from a YAML or JSON file."""
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"Scope file not found: {p}")
        text = p.read_text(encoding="utf-8")
        data = cls._load_text(text, p)
        return cls.from_dict(data)

    @staticmethod
    def _load_text(text: str, p: Path) -> dict[str, Any]:
        suffix = p.suffix.lower()
        if suffix == ".json":
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ScopeError(f"Invalid JSON scope file {p}: {exc}") from exc
        try:
            import yaml  # PyYAML
        except ImportError as exc:  # pragma: no cover
            raise ScopeError("PyYAML is required to read YAML scope files.") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeError(f"Invalid YAML scope file {p}: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError(f"Scope file {p} must contain a mapping at the top level.")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        if not isinstance(data, dict):
            raise ScopeError("Scope must be a mapping.")
        scope_block = data.get("scope") or {}
        if not isinstance(scope_block, dict):
            raise ScopeError("'scope' must be a mapping.")
        includes = [str(t) for t in (scope_block.get("targets") or [])]
        if not includes:
            raise ScopeError("Scope defines no targets under 'scope.targets'.")
        excludes = [str(t) for t in (scope_block.get("exclude") or [])]
        ports = [int(p) for p in (scope_block.get("ports") or [])]
        nameservers = [str(n) for n in (scope_block.get("nameservers") or [])]
        settings = data.get("settings") or {}
        authorization = Authorization.from_dict(data.get("authorization"))
        return cls(
            authorization=authorization,
            includes=includes,
            excludes=excludes,
            ports=ports,
            nameservers=nameservers,
            settings=settings,
            raw=data,
        )

    @classmethod
    def from_targets(cls, targets: list[str], *, authorized_via_cli: bool = False) -> "Scope":
        """Build an ad-hoc scope from ``--target`` values (no scope file).

        Authorization comes solely from the CLI ``--authorize`` flag in this mode.
        """
        authorization = Authorization.from_cli() if authorized_via_cli else Authorization()
        return cls(
            authorization=authorization,
            includes=list(targets),
            excludes=[],
            ports=[],
            nameservers=[],
            settings={},
            raw={"scope": {"targets": list(targets)}},
        )

    # -- parsing helpers -------------------------------------------------------------

    @staticmethod
    def _host_of(entry: str) -> str:
        """Extract the bare host/ip from an entry that may be a URL or host:port."""
        entry = entry.strip()
        if entry.startswith(("http://", "https://")):
            return (urlparse(entry).hostname or entry).lower()
        if entry.count(":") == 1 and not entry.startswith("["):
            host, _, port = entry.partition(":")
            if port.isdigit():
                return host.lower()
        return entry.lower()

    def _index(
        self,
        entries: list[str],
        networks: list,
        hosts: set,
        domains: set,
    ) -> None:
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            # CIDR range?
            if "/" in entry and not entry.startswith(("http://", "https://")):
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                    continue
                except ValueError:
                    pass  # not a network; fall through to host handling
            host = self._host_of(entry)
            # bare IP?
            try:
                ipaddress.ip_address(host)
                hosts.add(host)
                continue
            except ValueError:
                pass
            hosts.add(host)
            domains.add(host)

    # -- in-scope check (the safety gate) --------------------------------------------

    def is_in_scope(self, host: str) -> bool:
        """Return whether ``host`` (a hostname or IP) is in scope and not excluded."""
        host = (host or "").strip().lower()
        if not host:
            return False
        if self._matches(host, self._exc_networks, self._exc_hosts, self._exc_domains):
            return False
        return self._matches(host, self._inc_networks, self._inc_hosts, self._inc_domains)

    @staticmethod
    def _matches(host: str, networks: list, hosts: set, domains: set) -> bool:
        if host in hosts:
            return True
        # IP membership in any CIDR
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in net for net in networks):
                return True
        except ValueError:
            pass
        # domain or sub-domain suffix match (e.g. api.example.com matches example.com)
        for dom in domains:
            if host == dom or host.endswith("." + dom):
                return True
        return False

    # -- target expansion ------------------------------------------------------------

    def targets(self) -> list[Target]:
        """Expand scope includes into concrete :class:`Target` objects.

        CIDR ranges are expanded to per-host ``ip`` targets (capped by
        :data:`MAX_CIDR_HOSTS`). URLs become ``url`` targets, hostnames become
        ``domain``/``host`` targets. Order is preserved and duplicates removed.
        """
        out: list[Target] = []
        seen: set[str] = set()

        def add(t: Target) -> None:
            key = str(t)
            if key not in seen:
                seen.add(key)
                out.append(t)

        for entry in self.includes:
            entry = entry.strip()
            if not entry:
                continue
            if entry.startswith(("http://", "https://")):
                add(Target.from_string(entry))
                continue
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    add(Target.from_string(entry))
                    continue
                hosts_iter = net.hosts() if net.num_addresses > 2 else net
                for i, ip in enumerate(hosts_iter):
                    if i >= MAX_CIDR_HOSTS:
                        break
                    add(Target(raw=entry, host=str(ip), kind="ip"))
                continue
            target = Target.from_string(entry)
            # A bare hostname (not an IP, no port) is a domain — useful for DNS too.
            if target.kind == "host" and target.port is None:
                try:
                    ipaddress.ip_address(target.host)
                except ValueError:
                    target.kind = "domain"
            add(target)
        return out

    # -- misc ------------------------------------------------------------------------

    def parameterized_urls(self) -> list[str]:
        """Scope URLs that carry a query string (candidates for injection checks)."""
        urls = []
        for entry in self.includes:
            if entry.startswith(("http://", "https://")) and "?" in entry:
                urls.append(entry)
        return urls

    def summary(self) -> dict[str, Any]:
        return {
            "targets": self.includes,
            "exclude": self.excludes,
            "ports": self.ports,
            "nameservers": self.nameservers,
            "authorized_by": self.authorization.authorized_by,
            "engagement_id": self.authorization.engagement_id,
        }
