"""Loose, numeric-aware version comparison shared by the vuln-matching modules.

This is intentionally dependency-free and forgiving: it handles the messy version
strings seen in service banners and package manifests (``9.3p2``, ``1.3.5a``,
``2.4.49``, ``1.20.0``, ``4.17.21``) without requiring PEP 440 / semver parsing.
"""
from __future__ import annotations

import re
from typing import Any

_COMPONENT_RE = re.compile(r"(\d+)?([^.]*)")


def _split_component(component: str) -> tuple[int, str]:
    """Split a dotted component into (numeric_prefix, alpha_suffix).

    ``"3p2" -> (3, "p2")``, ``"49" -> (49, "")``, ``"5a" -> (5, "a")``.
    """
    m = _COMPONENT_RE.match(component)
    if not m:
        return (0, component)
    num = int(m.group(1)) if m.group(1) else 0
    return (num, m.group(2) or "")


def vercmp(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a`` <, ==, > ``b`` under loose ordering."""
    pa = str(a).strip().split(".")
    pb = str(b).strip().split(".")
    for i in range(max(len(pa), len(pb))):
        ca = pa[i] if i < len(pa) else "0"
        cb = pb[i] if i < len(pb) else "0"
        na, sa = _split_component(ca)
        nb, sb = _split_component(cb)
        if na != nb:
            return -1 if na < nb else 1
        if sa != sb:
            # A trailing suffix denotes a LATER patch level, so it sorts AFTER the
            # bare numeric component (e.g. "9.3p2" > "9.3", "1.3.5a" > "1.3.5").
            if sa == "":
                return -1
            if sb == "":
                return 1
            return -1 if sa < sb else 1
    return 0


def version_satisfies(version: str, affected: dict[str, Any]) -> bool:
    """Return True if ``version`` falls inside an ``affected`` constraint set.

    Recognised keys (all present keys must hold — logical AND):
      * ``versions``    — list of exact-match version strings
      * ``version_lt``  — vulnerable if version <  bound
      * ``version_le``  — vulnerable if version <= bound
      * ``version_gt``  — vulnerable if version >  bound
      * ``version_ge``  — vulnerable if version >= bound

    An empty/absent constraint set never matches (nothing asserts vulnerability).
    """
    if not affected:
        return False
    version = str(version).strip()
    if not version:
        return False

    exact = affected.get("versions")
    has_range = any(k in affected for k in ("version_lt", "version_le", "version_gt", "version_ge"))

    if exact is not None:
        if version in {str(v) for v in exact}:
            return True
        if not has_range:
            return False

    if not has_range:
        return False
    if "version_lt" in affected and not vercmp(version, affected["version_lt"]) < 0:
        return False
    if "version_le" in affected and not vercmp(version, affected["version_le"]) <= 0:
        return False
    if "version_gt" in affected and not vercmp(version, affected["version_gt"]) > 0:
        return False
    if "version_ge" in affected and not vercmp(version, affected["version_ge"]) >= 0:
        return False
    return True
