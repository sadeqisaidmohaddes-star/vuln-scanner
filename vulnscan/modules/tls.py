"""TLS/SSL posture analysis module.

This passive (non-intrusive) scanner inspects the TLS configuration exposed by a
target on its TLS port. It performs only what is required to *detect and report*
weaknesses — it never exploits, downgrades for gain, brute-forces, or stores any
target data beyond the certificate metadata needed for a finding.

Two kinds of checks are performed:

1. **Protocol enumeration** — for each legacy/current TLS version we attempt a
   single handshake that forces *exactly* that version. Successful handshakes
   against SSLv3 / TLS 1.0 / TLS 1.1 are reported as deprecated-protocol
   findings.
2. **Certificate + cipher inspection** — one permissive handshake collects the
   negotiated cipher suite and the peer certificate (DER), which is parsed with
   :mod:`cryptography` to surface expiry, self-signing, hostname mismatch, weak
   signature algorithms, and weak key sizes.

All network I/O goes through ``ctx.slot()`` (rate limiting / concurrency cap) and
every expected failure (timeout, connection refused, TLS/cert error, unsupported
protocol version) is caught — the module degrades gracefully and never raises.
"""
from __future__ import annotations

import asyncio
import ipaddress
import ssl
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from ..core.models import Finding, Severity, Target
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..core.context import ScanContext


# Ports on which TLS is conventionally spoken directly (implicit TLS).
TLS_PORTS: frozenset[int] = frozenset(
    {443, 8443, 993, 995, 465, 990, 636, 989, 5061}
)

# Mapping of human-friendly protocol names to the ``ssl.TLSVersion`` members we
# force for the single-version handshake probes. Order matters: highest first so
# the log/probe sequence reads naturally.
_PROTOCOLS: tuple[tuple[str, "ssl.TLSVersion"], ...] = (
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("SSLv3", ssl.TLSVersion.SSLv3),
)

# Deprecated protocols and the severity assigned when one is found enabled.
_DEPRECATED_SEVERITY: dict[str, Severity] = {
    "SSLv3": Severity.HIGH,
    "TLSv1.0": Severity.MEDIUM,
    "TLSv1.1": Severity.MEDIUM,
}

# Substrings (upper-cased) that mark a cipher suite as weak regardless of bits.
_WEAK_CIPHER_TOKENS: tuple[str, ...] = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")

# Number of days before expiry at which we warn that a certificate expires soon.
_EXPIRY_WARN_DAYS = 30


class TLSScanner(ScannerModule):
    """Analyse the TLS/SSL posture of a target's TLS endpoint."""

    name = "tls"
    description = "Analyse TLS/SSL posture: protocols, ciphers, and certificate health."
    category = "tls"
    default_severity = Severity.MEDIUM
    intrusive = False
    order = 20

    # -- applicability ---------------------------------------------------------------

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run for HTTPS, generic web targets, and probe-able host/ip/domain targets."""
        if target.scheme == "https":
            return True
        if target.is_web:
            return True
        return target.kind in {"host", "ip", "domain"}

    # -- main entry ------------------------------------------------------------------

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Probe the chosen TLS port and emit TLS/certificate findings."""
        host = target.host
        port = self._tls_port(target)
        findings: list[Finding] = []

        # 1) Protocol enumeration — one forced-version handshake per protocol.
        offered: dict[str, bool] = {}
        for proto_name, version in _PROTOCOLS:
            ok = await self._handshake_version(host, port, version, ctx)
            offered[proto_name] = ok
            if ok and proto_name in _DEPRECATED_SEVERITY:
                findings.append(self._deprecated_protocol_finding(proto_name, target, host, port))

        # If nothing handshook at all, the host almost certainly does not speak TLS
        # on this port — report nothing.
        if not any(offered.values()):
            ctx.log.debug("tls: %s:%s does not appear to speak TLS", host, port)
            return findings

        # The endpoint speaks TLS — record the service for the shared inventory.
        ctx.record_service(host=host, port=port, service="tls", source=self.name)

        # 2) Certificate + cipher inspection via one permissive handshake.
        cert_findings = await self._inspect_certificate_and_cipher(host, port, target, ctx)
        findings.extend(cert_findings)

        return findings

    # -- port selection --------------------------------------------------------------

    def _tls_port(self, target: "Target") -> int:
        """Pick the TLS port: target.port if it is a known TLS port, else 443."""
        if target.port and target.port in TLS_PORTS:
            return target.port
        return 443

    # -- protocol probe --------------------------------------------------------------

    async def _handshake_version(
        self,
        host: str,
        port: int,
        version: "ssl.TLSVersion",
        ctx: "ScanContext",
    ) -> bool:
        """Attempt a handshake forcing exactly ``version``; return success.

        Never raises: any failure (unsupported version, refused connection,
        timeout, TLS alert, OpenSSL build that disallows the version) is treated
        as "not offered".
        """
        try:
            ssl_ctx = self._single_version_context(version)
        except (ValueError, ssl.SSLError) as exc:
            # OpenSSL refuses to even configure this (old) version — not offered.
            ctx.log.debug("tls: cannot set version %s for %s:%s: %s", version, host, port, exc)
            return False

        writer: Optional[asyncio.StreamWriter] = None
        try:
            async with ctx.slot():
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
                    timeout=ctx.config.timeout,
                )
            return True
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
            ctx.log.debug("tls: handshake %s failed for %s:%s: %s", version, host, port, exc)
            return False
        finally:
            await self._close_writer(writer)

    @staticmethod
    def _single_version_context(version: "ssl.TLSVersion") -> ssl.SSLContext:
        """Build a permissive client context pinned to exactly ``version``."""
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx.minimum_version = version
        ssl_ctx.maximum_version = version
        # Some OpenSSL builds gate legacy ciphers behind SECLEVEL; relax so that a
        # genuinely-enabled legacy protocol is detectable rather than masked.
        try:
            ssl_ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        return ssl_ctx

    # -- certificate + cipher inspection ---------------------------------------------

    async def _inspect_certificate_and_cipher(
        self,
        host: str,
        port: int,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Run one permissive handshake and analyse the cipher + peer certificate."""
        findings: list[Finding] = []

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            ssl_ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

        writer: Optional[asyncio.StreamWriter] = None
        cipher: Optional[tuple[Any, ...]] = None
        der: Optional[bytes] = None
        try:
            async with ctx.slot():
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
                    timeout=ctx.config.timeout,
                )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                try:
                    cipher = ssl_object.cipher()
                except (ssl.SSLError, ValueError) as exc:
                    ctx.log.debug("tls: cipher() failed for %s:%s: %s", host, port, exc)
                try:
                    der = ssl_object.getpeercert(binary_form=True)
                except (ssl.SSLError, ValueError) as exc:
                    ctx.log.debug("tls: getpeercert failed for %s:%s: %s", host, port, exc)
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
            ctx.log.debug("tls: inspection handshake failed for %s:%s: %s", host, port, exc)
            return findings
        finally:
            await self._close_writer(writer)

        # Cipher analysis (negotiated suite).
        if cipher is not None:
            findings.extend(self._cipher_findings(cipher, target))

        # Certificate analysis (parsed with cryptography).
        if der:
            findings.extend(self._certificate_findings(der, host, target, ctx))

        return findings

    # -- cipher checks ---------------------------------------------------------------

    def _cipher_findings(self, cipher: tuple[Any, ...], target: "Target") -> list[Finding]:
        """Flag weak negotiated cipher suites."""
        findings: list[Finding] = []
        cipher_name = str(cipher[0]) if cipher and cipher[0] is not None else ""
        bits: Optional[int] = None
        if len(cipher) >= 3 and isinstance(cipher[2], int):
            bits = cipher[2]

        upper = cipher_name.upper()
        weak_token = any(token in upper for token in _WEAK_CIPHER_TOKENS)
        weak_bits = bits is not None and bits < 128
        if weak_token or weak_bits:
            findings.append(
                self.finding(
                    title=f"Weak TLS cipher negotiated: {cipher_name}",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server negotiated a cryptographically weak cipher suite "
                        f"({cipher_name!r}, {bits if bits is not None else 'unknown'} bits). "
                        "Weak ciphers (RC4, DES/3DES, EXPORT, NULL, or <128-bit keys) "
                        "are vulnerable to known cryptanalytic attacks."
                    ),
                    target=target,
                    evidence={
                        "cipher": cipher_name,
                        "protocol": str(cipher[1]) if len(cipher) >= 2 else "",
                        "bits": bits,
                    },
                    remediation=(
                        "Disable weak cipher suites and prefer modern AEAD ciphers "
                        "(e.g. AES-GCM, ChaCha20-Poly1305) with at least 128-bit "
                        "effective strength."
                    ),
                    references=["CWE-327"],
                    confidence="firm",
                )
            )
        return findings

    # -- certificate checks ----------------------------------------------------------

    def _certificate_findings(
        self,
        der: bytes,
        host: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Parse the DER certificate and surface certificate-level issues."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError as exc:  # pragma: no cover - dependency missing
            ctx.log.debug("tls: cryptography unavailable, skipping cert checks: %s", exc)
            return []

        try:
            cert = x509.load_der_x509_certificate(der)
        except (ValueError, TypeError) as exc:
            ctx.log.debug("tls: failed to parse certificate for %s: %s", host, exc)
            return []

        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        # -- validity window ------------------------------------------------------
        not_before = self._cert_not_before(cert)
        not_after = self._cert_not_after(cert)
        nb_str = not_before.isoformat() if not_before else None
        na_str = not_after.isoformat() if not_after else None

        if not_after is not None and not_after < now:
            findings.append(
                self.finding(
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    description=(
                        f"The server's TLS certificate expired on {na_str}. Clients will "
                        "refuse the connection or present security warnings."
                    ),
                    target=target,
                    evidence={"not_before": nb_str, "not_after": na_str, "checked_at": now.isoformat()},
                    remediation="Renew and deploy a valid certificate from a trusted CA.",
                    references=["CWE-298", "CWE-295"],
                    confidence="firm",
                )
            )
        elif not_after is not None and not_after <= now + timedelta(days=_EXPIRY_WARN_DAYS):
            days_left = max((not_after - now).days, 0)
            findings.append(
                self.finding(
                    title="TLS certificate expires soon",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The server's TLS certificate expires on {na_str} "
                        f"(~{days_left} day(s) from now), within the {_EXPIRY_WARN_DAYS}-day "
                        "warning window."
                    ),
                    target=target,
                    evidence={
                        "not_before": nb_str,
                        "not_after": na_str,
                        "days_left": days_left,
                        "checked_at": now.isoformat(),
                    },
                    remediation="Renew the certificate before it expires to avoid an outage.",
                    references=["CWE-298"],
                    confidence="firm",
                )
            )

        if not_before is not None and not_before > now:
            findings.append(
                self.finding(
                    title="TLS certificate not yet valid",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The server's TLS certificate is not valid until {nb_str}; its "
                        "validity period has not yet begun (possible clock skew or "
                        "premature deployment)."
                    ),
                    target=target,
                    evidence={"not_before": nb_str, "not_after": na_str, "checked_at": now.isoformat()},
                    remediation=(
                        "Deploy a certificate whose validity period covers the current "
                        "date and verify server clock synchronisation."
                    ),
                    references=["CWE-295"],
                    confidence="firm",
                )
            )

        # -- self-signed ----------------------------------------------------------
        try:
            is_self_signed = cert.issuer == cert.subject
        except Exception as exc:  # pragma: no cover - defensive
            ctx.log.debug("tls: issuer/subject comparison failed for %s: %s", host, exc)
            is_self_signed = False
        if is_self_signed:
            findings.append(
                self.finding(
                    title="Self-signed certificate",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server presents a self-signed certificate (issuer equals "
                        "subject). Self-signed certificates are not anchored to a trusted "
                        "CA and cannot be validated by default-trusting clients."
                    ),
                    target=target,
                    evidence={
                        "subject": self._name_to_str(cert.subject),
                        "issuer": self._name_to_str(cert.issuer),
                    },
                    remediation=(
                        "Replace the self-signed certificate with one issued by a "
                        "trusted certificate authority."
                    ),
                    references=["CWE-295"],
                    confidence="firm",
                )
            )

        # -- hostname match (skip IP literals) ------------------------------------
        if not self._is_ip_literal(host):
            names = self._cert_dns_names(cert, x509)
            cn = self._cert_common_name(cert, x509)
            if cn:
                names = names + [cn]
            if names and not self._hostname_matches(host, names):
                findings.append(
                    self.finding(
                        title="Certificate hostname mismatch",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The connect host {host!r} does not match any name in the "
                            "certificate (SAN dNSNames or CN). Clients will reject the "
                            "connection as a possible impersonation."
                        ),
                        target=target,
                        evidence={"connect_host": host, "certificate_names": names},
                        remediation=(
                            "Issue a certificate whose Subject Alternative Names include "
                            "the hostname clients use to reach this service."
                        ),
                        references=["CWE-295", "CWE-297"],
                        confidence="firm",
                    )
                )

        # -- weak signature algorithm --------------------------------------------
        sig_alg = self._signature_hash_name(cert)
        if sig_alg and sig_alg.lower() in {"sha1", "md5"}:
            findings.append(
                self.finding(
                    title=f"Weak certificate signature algorithm: {sig_alg}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The certificate is signed using {sig_alg}, a hash algorithm "
                        "with known collision weaknesses that is no longer trusted for "
                        "certificate signatures."
                    ),
                    target=target,
                    evidence={"signature_algorithm": sig_alg},
                    remediation=(
                        "Reissue the certificate using a SHA-256 (or stronger) signature."
                    ),
                    references=["CWE-327"],
                    confidence="firm",
                )
            )

        # -- weak RSA key size ----------------------------------------------------
        key_findings = self._weak_key_findings(cert, rsa, target, ctx)
        findings.extend(key_findings)

        return findings

    # -- certificate helpers ---------------------------------------------------------

    @staticmethod
    def _cert_not_after(cert: Any) -> Optional[datetime]:
        """Return the certificate's not-valid-after as a tz-aware UTC datetime."""
        value = getattr(cert, "not_valid_after_utc", None)
        if value is None:
            value = getattr(cert, "not_valid_after", None)
            if value is not None and value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

    @staticmethod
    def _cert_not_before(cert: Any) -> Optional[datetime]:
        """Return the certificate's not-valid-before as a tz-aware UTC datetime."""
        value = getattr(cert, "not_valid_before_utc", None)
        if value is None:
            value = getattr(cert, "not_valid_before", None)
            if value is not None and value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

    @staticmethod
    def _signature_hash_name(cert: Any) -> str:
        """Return the certificate signature hash algorithm name, or '' if unknown."""
        try:
            alg = cert.signature_hash_algorithm
        except Exception:  # pragma: no cover - defensive
            return ""
        name = getattr(alg, "name", None)
        return str(name) if name else ""

    @staticmethod
    def _cert_dns_names(cert: Any, x509: Any) -> list[str]:
        """Extract SAN dNSName entries, returning [] on any error/absence."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            return []

    @staticmethod
    def _cert_common_name(cert: Any, x509: Any) -> str:
        """Extract the subject CommonName (CN), or '' if absent."""
        try:
            attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        except Exception:
            return ""
        if not attrs:
            return ""
        value = attrs[0].value
        return value if isinstance(value, str) else str(value)

    @staticmethod
    def _name_to_str(name: Any) -> str:
        """Best-effort RFC4514 string for an x509 Name."""
        try:
            return name.rfc4514_string()
        except Exception:  # pragma: no cover - defensive
            return str(name)

    def _weak_key_findings(
        self,
        cert: Any,
        rsa: Any,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Flag RSA public keys smaller than 2048 bits."""
        try:
            public_key = cert.public_key()
        except Exception as exc:  # pragma: no cover - defensive
            ctx.log.debug("tls: public_key() failed: %s", exc)
            return []
        if not isinstance(public_key, rsa.RSAPublicKey):
            return []
        bits = public_key.key_size
        if bits >= 2048:
            return []
        return [
            self.finding(
                title=f"Weak certificate key size: {bits}-bit RSA",
                severity=Severity.MEDIUM,
                description=(
                    f"The certificate uses a {bits}-bit RSA public key, below the "
                    "2048-bit minimum recommended for adequate security margin."
                ),
                target=target,
                evidence={"key_type": "RSA", "key_size_bits": bits},
                remediation=(
                    "Reissue the certificate with at least a 2048-bit RSA key "
                    "(or an equivalent-strength ECDSA key)."
                ),
                references=["CWE-326"],
                confidence="firm",
            )
        ]

    # -- protocol finding builder ----------------------------------------------------

    def _deprecated_protocol_finding(
        self,
        proto_name: str,
        target: "Target",
        host: str,
        port: int,
    ) -> Finding:
        """Build a finding for a deprecated TLS/SSL protocol that handshook."""
        severity = _DEPRECATED_SEVERITY[proto_name]
        return self.finding(
            title=f"Deprecated TLS protocol enabled: {proto_name}",
            severity=severity,
            description=(
                f"The server completed a handshake using {proto_name}, a deprecated "
                "protocol with known cryptographic weaknesses (e.g. POODLE, BEAST). "
                "Supporting it exposes clients to downgrade and decryption attacks."
            ),
            target=target,
            evidence={"protocol": proto_name, "host": host, "port": port},
            remediation=(
                "Disable SSLv3, TLS 1.0, and TLS 1.1 on the server; require TLS 1.2 "
                "or TLS 1.3 only."
            ),
            references=["CWE-327"],
            confidence="firm",
        )

    # -- hostname matching -----------------------------------------------------------

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        """Whether ``host`` is an IPv4/IPv6 literal (hostname matching is skipped)."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _hostname_matches(self, host: str, names: list[str]) -> bool:
        """Return whether ``host`` matches any certificate name (with wildcards)."""
        host = host.strip(".").lower()
        for name in names:
            if self._match_one(host, name.strip(".").lower()):
                return True
        return False

    @staticmethod
    def _match_one(host: str, pattern: str) -> bool:
        """Match a single hostname against a (possibly wildcard) cert name."""
        if not pattern:
            return False
        if pattern == host:
            return True
        # Leftmost-label wildcard: "*.example.com" matches "a.example.com" but not
        # "example.com" and not "a.b.example.com".
        if pattern.startswith("*."):
            suffix = pattern[1:]  # includes the leading dot, e.g. ".example.com"
            if not host.endswith(suffix):
                return False
            left = host[: -len(suffix)]
            return bool(left) and "." not in left
        return False

    # -- stream cleanup --------------------------------------------------------------

    @staticmethod
    async def _close_writer(writer: Optional["asyncio.StreamWriter"]) -> None:
        """Close a stream writer, swallowing any teardown errors."""
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            pass
        except Exception:  # pragma: no cover - defensive teardown
            pass
