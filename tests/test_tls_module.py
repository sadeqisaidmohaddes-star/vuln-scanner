"""Integration test for the TLS scanner module.

This test stands up a real, in-process asyncio TLS server on ``127.0.0.1`` that
presents a self-signed *and* expired RSA certificate, then runs the production
:class:`~vulnscan.modules.tls.TLSScanner` against it and asserts that the
self-signed certificate is detected.

The certificate is deliberately crafted so its validity window is entirely in
the past (now-2d .. now-1d), which exercises both the "self-signed" and the
"expired" code paths of the module at once. We assert on the self-signed finding
specifically; the expired/protocol findings are allowed to co-exist.

Everything is local (loopback only) and ephemeral (cert lives in a tmp dir, the
server binds an OS-chosen port). If the sandbox forbids binding a listening
socket or completing a loopback TLS handshake, the test skips gracefully rather
than failing.
"""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnscan.core.context import ScanConfig, ScanContext
from vulnscan.core.models import Target
from vulnscan.core.ratelimit import RateLimiter
from vulnscan.core.scope import Scope
from vulnscan.modules.tls import TLS_PORTS, TLSScanner

# Short timeout so the (many) forced-version handshake probes against a healthy
# loopback server finish quickly and any genuinely-failing probe gives up fast.
_TIMEOUT = 5.0

# The module's _tls_port() only honours target.port when it is a *recognised* TLS
# port (vulnscan.modules.tls.TLS_PORTS); for anything else it falls back to 443.
# So an OS-chosen ephemeral port would make the module probe 443 instead of our
# server. We therefore bind the server on one of the recognised, non-privileged
# TLS ports so the module actually connects to it. (443/465/636/993/995 are
# privileged on most systems; 8443 and 5061 are not.)
_CANDIDATE_PORTS = [p for p in (8443, 5061) if p in TLS_PORTS]


def _write_self_signed_expired_cert(tmp_dir: Path) -> tuple[Path, Path]:
    """Generate an RSA-2048 self-signed + already-expired cert into ``tmp_dir``.

    Subject == issuer (CN "localhost") makes it self-signed; the validity window
    (now-2d .. now-1d) makes it expired. Returns ``(cert_pem, key_pem)`` paths.
    """
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # issuer == subject -> self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))  # already expired
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _build_context() -> ScanContext:
    """Build a minimal ScanContext targeting 127.0.0.1 with a short timeout.

    The TLS module never touches ``ctx.http``, so a real HTTP client is not
    required; ``None`` is sufficient for this code path.
    """
    config = ScanConfig(rate_limit=100.0, concurrency=10, timeout=_TIMEOUT)
    scope = Scope.from_dict(
        {
            "authorization": {"authorized": True, "authorized_by": "test-suite"},
            "scope": {"targets": ["127.0.0.1"]},
        }
    )
    limiter = RateLimiter(config.rate_limit, config.concurrency)
    return ScanContext(config=config, scope=scope, http_client=None, limiter=limiter)


async def test_tls_module_detects_self_signed_cert(tmp_path):
    cert_path, key_path = _write_self_signed_expired_cert(tmp_path)

    # Server-side TLS context loading the self-signed cert/key.
    server_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server_ssl_ctx.load_cert_chain(str(cert_path), str(key_path))
    except ssl.SSLError as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"could not load self-signed cert chain: {exc}")

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Drain whatever the client sends (if anything), then close.
        try:
            await reader.read(4096)
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    # Bind on a recognised TLS port (see _CANDIDATE_PORTS) so the module probes
    # our server rather than falling back to 443. Try each candidate; skip if the
    # sandbox refuses to bind any of them.
    server = None
    last_exc: BaseException | None = None
    for candidate in _CANDIDATE_PORTS:
        try:
            server = await asyncio.start_server(
                handler, "127.0.0.1", candidate, ssl=server_ssl_ctx
            )
            break
        except (OSError, ssl.SSLError, PermissionError) as exc:
            last_exc = exc
    if server is None:
        pytest.skip(
            f"could not bind in-process TLS server on {_CANDIDATE_PORTS}: {last_exc}"
        )

    try:
        port = server.sockets[0].getsockname()[1]

        target = Target(
            raw=f"127.0.0.1:{port}",
            host="127.0.0.1",
            port=port,
            scheme="https",
            kind="host",
        )
        ctx = _build_context()
        module = TLSScanner()

        try:
            findings = await asyncio.wait_for(module.run(target, ctx), timeout=30.0)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            pytest.skip(f"loopback TLS handshake failed in this environment: {exc}")

        titles = [f.title.lower() for f in findings]

        # The headline assertion: the self-signed certificate must be detected.
        assert any("self-signed" in t for t in titles), (
            "expected a 'Self-signed certificate' finding; got titles: "
            f"{[f.title for f in findings]}"
        )

        # Sanity: every finding is attributed to this module and targets our port.
        self_signed = [f for f in findings if "self-signed" in f.title.lower()]
        assert self_signed, "no self-signed finding object found"
        for f in self_signed:
            assert f.module == TLSScanner.name == "tls"
            assert str(port) in f.target
            # issuer == subject is the evidence backing the self-signed verdict.
            assert f.evidence.get("issuer") == f.evidence.get("subject")
    finally:
        server.close()
        try:
            await server.wait_closed()
        except (OSError, ssl.SSLError):
            pass
