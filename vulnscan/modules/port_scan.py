"""Async TCP connect port scanner with light service/version identification.

This module performs a non-destructive TCP *connect* scan over the scoped ports
(``ctx.scope.ports``). A successful three-way handshake marks a port OPEN. For
each open port it performs a single, best-effort banner grab — reading whatever
the service volunteers (SSH/FTP/SMTP greet first), and for known HTTP ports that
stay silent it sends one minimal ``HEAD / HTTP/1.0`` request and reads the
response once. From the banner it derives a coarse service name plus, where a
small defensive regex matches, a product and version string.

Everything here is detection-and-reporting only: it never authenticates, never
sends a payload beyond a single benign HTTP ``HEAD``, and never stores target
file contents. Each open port yields an INFO finding (with the observation also
pushed into the shared inventory for the ``vuln_match`` correlator), and a small
set of clearly sensitive exposed services (telnet, ftp, smb, rdp, databases) are
elevated to LOW so that a reviewer notices network-exposure issues.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Optional

from ..core.models import Finding, Severity, Target
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # avoid import cost / cycles at module import time
    from ..core.context import ScanContext


# Common TCP port -> coarse service name. Kept small and conservative; unknown
# ports simply report an empty service name.
_PORT_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Ports we treat as HTTP-speaking for the optional benign HEAD probe when the
# service does not greet on its own.
_HTTP_PORTS: frozenset[int] = frozenset({80, 443, 3000, 8000, 8080, 8443, 8888})

# Ports for which an open exposure is, on its own, worth flagging at LOW because
# the service is high-value, frequently misconfigured, or plaintext.
_SENSITIVE_PORTS: frozenset[int] = frozenset(
    {
        23,     # telnet (plaintext remote shell)
        21,     # ftp (often plaintext / anonymous)
        445,    # smb
        3389,   # rdp
        3306,   # mysql
        5432,   # postgresql
        6379,   # redis (frequently unauthenticated)
        9200,   # elasticsearch
        27017,  # mongodb
        5900,   # vnc
        11211,  # memcached
    }
)

# Defensive product/version extractors. Each entry maps a service hint (or "*"
# for "try against any banner") to (compiled_regex, product_name). The regex
# must expose a named group ``ver`` for the version; ``product`` may be a fixed
# string or ``None`` to take the regex's ``prod`` group instead.
_BANNER_PATTERNS: list[tuple[re.Pattern[str], Optional[str]]] = [
    # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3 -> OpenSSH 8.9p1
    (re.compile(r"SSH-\d+\.\d+-(?P<prod>OpenSSH)[_/](?P<ver>[\w.\-]+)", re.I), None),
    # Generic SSH banner: SSH-2.0-<product>_<version>
    (re.compile(r"SSH-\d+\.\d+-(?P<prod>[A-Za-z][\w.\-]*?)[_/](?P<ver>[\d][\w.\-]*)", re.I), None),
    # 220 ProFTPD 1.3.5 Server / 220 (vsFTPd 3.0.3)
    (re.compile(r"\b(?P<prod>ProFTPD|vsFTPd|Pure-FTPd|FileZilla)\b[^\d]{0,12}(?P<ver>\d[\w.\-]*)", re.I), None),
    # SMTP/IMAP/POP greetings: ... Postfix / Exim 4.94 / Dovecot
    (re.compile(r"\b(?P<prod>Postfix|Exim|Sendmail|Dovecot)\b[^\d]{0,12}(?P<ver>\d[\w.\-]*)?", re.I), None),
    # HTTP Server header: Server: nginx/1.18.0  |  Apache/2.4.41
    (re.compile(r"Server:\s*(?P<prod>[A-Za-z][\w.\-]*)/(?P<ver>\d[\w.\-]*)", re.I), None),
    # Redis INFO-style greeting is rare on connect; match a version token if shown.
    (re.compile(r"redis_version:(?P<ver>\d[\w.\-]*)", re.I), "Redis"),
    # MySQL handshake leaks a readable version like 5.7.40 / 8.0.32 near the start.
    (re.compile(r"(?P<ver>\d+\.\d+\.\d+)(?:-\w+)?-?MariaDB", re.I), "MariaDB"),
]


def _service_for(port: int) -> str:
    """Return the coarse service label for ``port`` (empty string if unknown)."""
    return _PORT_SERVICES.get(port, "")


def _trim_banner(banner: str, limit: int = 200) -> str:
    """Collapse control characters and trim a banner to ``limit`` characters."""
    if not banner:
        return ""
    # Replace runs of whitespace/control chars with a single space for readability.
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+", " ", banner)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned


def _parse_product_version(banner: str) -> tuple[str, str]:
    """Best-effort ``(product, version)`` extraction from a raw banner.

    Always defensive: any non-match simply yields empty strings, and a failed
    regex group never raises.
    """
    if not banner:
        return "", ""
    for pattern, fixed_product in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if not match:
            continue
        groups = match.groupdict()
        product = fixed_product or (groups.get("prod") or "")
        version = groups.get("ver") or ""
        product = product.strip()
        version = version.strip()
        if product or version:
            return product, version
    return "", ""


class PortScan(ScannerModule):
    """TCP connect scan over scoped ports with light banner identification."""

    name = "port_scan"
    description = "Async TCP connect scan with light banner/service/version identification"
    category = "network"
    default_severity = Severity.INFO
    intrusive = True
    order = 10

    # Service-name hints used to decide what (if anything) to actively probe.
    _READ_LIMIT = 1024

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run on host/ip/domain targets; skip pure ``url`` targets."""
        return target.kind in {"host", "ip", "domain"}

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Connect-scan every scoped port and emit a finding per open port."""
        ports = list(ctx.scope.ports or [])
        if not ports:
            ctx.log.debug("port_scan: no ports in scope for %s", target.host)
            return []

        tasks = [self._probe_port(target, ctx, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for port, result in zip(ports, results):
            if isinstance(result, BaseException):
                # _probe_port is written not to raise; this is a last-resort guard.
                ctx.log.debug(
                    "port_scan: unexpected error probing %s:%s -> %r",
                    target.host,
                    port,
                    result,
                )
                continue
            if result is not None:
                findings.append(result)
        return findings

    async def _probe_port(
        self,
        target: "Target",
        ctx: "ScanContext",
        port: int,
    ) -> Optional[Finding]:
        """Probe a single ``port``; return a Finding if open, else ``None``.

        Catches all expected network failures (closed/filtered ports, timeouts,
        TLS/connection errors) and returns ``None`` so the caller can continue.
        """
        writer = None
        banner = ""
        try:
            reader, writer = await ctx.open_connection(target.host, port)
        except (asyncio.TimeoutError, OSError) as exc:
            # Closed, filtered, refused, or unreachable — not an open port.
            ctx.log.debug("port_scan: %s:%s not open (%s)", target.host, port, exc)
            return None
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug("port_scan: %s:%s connect error %r", target.host, port, exc)
            return None

        try:
            banner = await self._grab_banner(target, ctx, port, reader, writer)
        except (asyncio.TimeoutError, OSError) as exc:
            ctx.log.debug("port_scan: %s:%s banner read failed (%s)", target.host, port, exc)
        except Exception as exc:  # pragma: no cover - defensive catch-all
            ctx.log.debug("port_scan: %s:%s banner error %r", target.host, port, exc)
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:  # pragma: no cover - best-effort close
                    pass

        return self._build_finding(target, ctx, port, banner)

    async def _grab_banner(
        self,
        target: "Target",
        ctx: "ScanContext",
        port: int,
        reader: "asyncio.StreamReader",
        writer: "asyncio.StreamWriter",
    ) -> str:
        """Read a short banner, optionally nudging silent HTTP ports with HEAD."""
        read_timeout = min(2.0, float(ctx.config.timeout))

        # First, give services that greet on connect (SSH/FTP/SMTP/...) a chance.
        try:
            data = await asyncio.wait_for(reader.read(self._READ_LIMIT), timeout=read_timeout)
        except (asyncio.TimeoutError, OSError):
            data = b""

        if data:
            return data.decode("latin-1", errors="replace")

        # Silent socket: for known HTTP ports send a single benign HEAD request
        # and read the response headers once. No payload, no body, nothing stored.
        if port in _HTTP_PORTS:
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {target.host}\r\n"
                "User-Agent: vulnscan/0.1 (+authorized-security-assessment)\r\n\r\n"
            ).encode("latin-1", errors="ignore")
            try:
                writer.write(request)
                await asyncio.wait_for(writer.drain(), timeout=read_timeout)
                data = await asyncio.wait_for(
                    reader.read(self._READ_LIMIT), timeout=read_timeout
                )
            except (asyncio.TimeoutError, OSError):
                data = b""
            if data:
                return data.decode("latin-1", errors="replace")

        return ""

    def _build_finding(
        self,
        target: "Target",
        ctx: "ScanContext",
        port: int,
        banner: str,
    ) -> Finding:
        """Construct the finding for an open port and record the observation."""
        service = _service_for(port)
        product, version = _parse_product_version(banner)
        trimmed = _trim_banner(banner)

        # Always feed the shared inventory so vuln_match can correlate later.
        ctx.record_service(
            host=target.host,
            port=port,
            service=service,
            product=product,
            version=version,
            source=self.name,
            raw_banner=trimmed,
        )

        evidence = {
            "port": port,
            "service": service or "unknown",
            "product": product,
            "version": version,
            "banner": trimmed,
        }

        service_label = service or "unknown"

        if port in _SENSITIVE_PORTS:
            title = f"Sensitive service exposed: {service_label} on {port}/tcp"
            severity = Severity.LOW
            description = (
                f"A sensitive service ({service_label}) is reachable on "
                f"{target.host}:{port}/tcp. Services like this (remote admin, "
                "plaintext protocols, and databases) are high-value targets and "
                "are frequently misconfigured or left unauthenticated. Exposure "
                "to untrusted networks materially increases attack surface."
            )
            remediation = (
                "Restrict access to this service at the network layer: bind it to "
                "localhost or a private interface, place it behind a VPN or "
                "firewall, and allow-list only the hosts that require it. Disable "
                "the service entirely if it is not needed, and ensure strong "
                "authentication and transport encryption where it is."
            )
        else:
            title = f"Open port {port}/tcp ({service_label})"
            severity = Severity.INFO
            description = (
                f"TCP port {port} ({service_label}) is open on {target.host}. "
                "This is informational reconnaissance output establishing the "
                "exposed network surface; the banner (if any) is included to aid "
                "service and version identification."
            )
            remediation = (
                "Confirm that this port is intentionally exposed. Close or "
                "firewall any ports that are not required for the service to "
                "function, and keep the running software patched."
            )

        confidence = "firm" if (product or version or trimmed) else "tentative"

        return self.finding(
            title=title,
            severity=severity,
            description=description,
            target=target,
            evidence=evidence,
            remediation=remediation,
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://cwe.mitre.org/data/definitions/284.html",
            ],
            confidence=confidence,
        )
