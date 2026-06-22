"""vulnscan — a modular vulnerability scanner for *authorized* security assessments.

This is a DETECTION-AND-REPORTING tool. Modules identify misconfigurations,
exposures, and known-vulnerable software versions and emit structured findings;
they do not exploit, exfiltrate, or perform destructive actions.

Public surface:
    from vulnscan import ScannerModule, Finding, Severity, Target, ScanContext
"""
from __future__ import annotations

from .core.models import Finding, ScanResult, Severity, Target
from .core.module_base import ScannerModule
from .core.context import ScanConfig, ScanContext, Inventory, ServiceObservation
from .core.scope import Scope
from .core.authorization import Authorization

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "Target",
    "ScannerModule",
    "ScanConfig",
    "ScanContext",
    "Inventory",
    "ServiceObservation",
    "Scope",
    "Authorization",
    "__version__",
]
