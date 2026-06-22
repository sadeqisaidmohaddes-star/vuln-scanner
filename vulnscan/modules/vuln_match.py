"""Correlate observed services against the local known-vulnerability signature DB.

This is a passive correlation module: it performs no network I/O of its own.
Instead it runs late (``order = 90``) so that discovery modules (port scanning,
TLS, HTTP banner grabbing) have already populated ``ctx.inventory`` with
:class:`~vulnscan.core.context.ServiceObservation` records. For each observed
service that carries both a product name and a version, it checks every entry in
the bundled signature database (``vuln_signatures.json``) and emits a
:class:`~vulnscan.core.models.Finding` for each known-vulnerable match.

Matching is intentionally conservative and offline:

* ``product`` matches when the signature's product is a case-insensitive
  substring of the observed product.
* ``service`` (optional) must equal the observed service, case-insensitively.
* the observed version must satisfy every ``affected`` constraint (logical AND).

Version comparison uses :func:`_vercmp`, a small numeric-aware comparator that
handles the loose dotted-with-suffix versions seen in real banners (e.g.
``"9.3p2"``, ``"1.3.5a"``, ``"2.4.50"``) without any third-party dependency.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.datafiles import load_json
from ..core.models import Finding, Severity, Target

if TYPE_CHECKING:  # avoid import cost / cycles at module import time
    from ..core.context import ScanContext, ServiceObservation


# ---------------------------------------------------------------------------
# Loose, numeric-aware version comparison (pure Python, no external library).
# ---------------------------------------------------------------------------

def _split_component(component: str) -> tuple[int, str]:
    """Split one dotted component into a leading integer part and a trailing alpha part.

    The component is parsed as ``<digits><rest>``: the leading run of ASCII
    digits becomes the integer part (``0`` when absent), and everything after it
    is kept verbatim as the alphanumeric suffix used for tie-breaking.

    Examples::

        _split_component("3p2") -> (3, "p2")
        _split_component("5a")  -> (5, "a")
        _split_component("49")  -> (49, "")
        _split_component("")    -> (0, "")
        _split_component("rc")  -> (0, "rc")
    """
    i = 0
    n = len(component)
    while i < n and component[i].isdigit():
        i += 1
    num = int(component[:i]) if i > 0 else 0
    return num, component[i:]


def _vercmp(a: str, b: str) -> int:
    """Compare two loose version strings, returning ``-1``, ``0`` or ``1``.

    Each version is split on ``'.'`` into components; each component is further
    split into a numeric prefix and an alphanumeric suffix via
    :func:`_split_component`. Components are compared pairwise: integer parts
    numerically first, then suffixes lexicographically. Missing components are
    treated as ``(0, "")`` so that, for example, ``"9.3p2" > "9.3"`` and
    ``"1.3.5a" > "1.3.5"`` while ``"1.20.0" < "1.21.0"``.
    """
    parts_a = (a or "").split(".")
    parts_b = (b or "").split(".")
    length = max(len(parts_a), len(parts_b))
    for idx in range(length):
        comp_a = parts_a[idx] if idx < len(parts_a) else ""
        comp_b = parts_b[idx] if idx < len(parts_b) else ""
        num_a, suf_a = _split_component(comp_a)
        num_b, suf_b = _split_component(comp_b)
        if num_a != num_b:
            return -1 if num_a < num_b else 1
        if suf_a != suf_b:
            return -1 if suf_a < suf_b else 1
    return 0


def _lt(a: str, b: str) -> bool:
    """Return whether version ``a`` is strictly less than version ``b``."""
    return _vercmp(a, b) < 0


def _le(a: str, b: str) -> bool:
    """Return whether version ``a`` is less than or equal to version ``b``."""
    return _vercmp(a, b) <= 0


def _gt(a: str, b: str) -> bool:
    """Return whether version ``a`` is strictly greater than version ``b``."""
    return _vercmp(a, b) > 0


def _ge(a: str, b: str) -> bool:
    """Return whether version ``a`` is greater than or equal to version ``b``."""
    return _vercmp(a, b) >= 0


# ---------------------------------------------------------------------------
# The module.
# ---------------------------------------------------------------------------

from ..core.module_base import ScannerModule  # noqa: E402  (after helpers for readability)


class VulnMatchModule(ScannerModule):
    """Report known-vulnerable software by matching the inventory to the signature DB."""

    name = "vuln_match"
    description = "Correlate observed service/product/version against the known-vulnerability signature DB"
    category = "vuln"
    default_severity = Severity.HIGH
    intrusive = False
    order = 90  # run after discovery modules have populated the inventory

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Always applicable; per-host filtering happens inside :meth:`run`."""
        return True

    @staticmethod
    def _affected(version: str, affected: dict) -> bool:
        """Return whether ``version`` satisfies every present ``affected`` constraint.

        All present keys are combined with logical AND. ``versions`` is an exact
        membership test; ``version_lt``/``version_le``/``version_gt``/``version_ge``
        use the loose numeric-aware comparator. An empty/missing constraint set
        never matches (there is nothing to assert vulnerability against).
        """
        if not affected:
            return False
        versions = affected.get("versions")
        if versions is not None and version not in versions:
            return False
        bound = affected.get("version_lt")
        if bound is not None and not _lt(version, bound):
            return False
        bound = affected.get("version_le")
        if bound is not None and not _le(version, bound):
            return False
        bound = affected.get("version_gt")
        if bound is not None and not _gt(version, bound):
            return False
        bound = affected.get("version_ge")
        if bound is not None and not _ge(version, bound):
            return False
        # Require at least one constraint to have been present.
        return any(
            key in affected
            for key in ("versions", "version_lt", "version_le", "version_gt", "version_ge")
        )

    @staticmethod
    def _matches_signature(observation: "ServiceObservation", signature: dict) -> bool:
        """Return whether ``observation`` matches ``signature`` (product/service/version)."""
        sig_product = str(signature.get("product", "")).lower()
        if not sig_product or sig_product not in observation.product.lower():
            return False
        sig_service = signature.get("service")
        if sig_service is not None:
            if str(sig_service).lower() != (observation.service or "").lower():
                return False
        return VulnMatchModule._affected(observation.version, signature.get("affected") or {})

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Match this host's observed services against the local signature DB."""
        findings: list[Finding] = []

        try:
            db = load_json("vuln_signatures.json")
            signatures = db["signatures"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            ctx.log.debug("vuln_match: could not load signature DB: %s", exc)
            return findings

        if not isinstance(signatures, list):
            ctx.log.debug("vuln_match: signature DB 'signatures' is not a list")
            return findings

        observations = ctx.inventory.for_host(target.host)
        for observation in observations:
            if not observation.product or not observation.version:
                continue
            for signature in signatures:
                if not isinstance(signature, dict):
                    continue
                try:
                    if not self._matches_signature(observation, signature):
                        continue
                except (TypeError, ValueError) as exc:  # malformed signature entry
                    ctx.log.debug(
                        "vuln_match: skipping malformed signature %r: %s",
                        signature.get("id"),
                        exc,
                    )
                    continue

                cve = signature.get("cve")
                cwe = signature.get("cwe")
                references: list[str] = [
                    *([cve] if cve else []),
                    *([cwe] if cwe else []),
                    *signature.get("references", []),
                ]
                try:
                    severity = Severity.from_str(str(signature.get("severity", "")))
                except ValueError:
                    severity = self.default_severity

                findings.append(
                    self.finding(
                        title=signature.get("title", "Known-vulnerable software detected"),
                        severity=severity,
                        description=signature.get("description", ""),
                        target=target,
                        evidence={
                            "product": observation.product,
                            "version": observation.version,
                            "port": observation.port,
                            "signature_id": signature.get("id"),
                            "cve": cve,
                            "cwe": cwe,
                        },
                        remediation=(
                            "Upgrade " + observation.product
                            + " to a fixed release; see referenced advisory."
                        ),
                        references=references,
                        confidence="firm",
                    )
                )

        return findings
