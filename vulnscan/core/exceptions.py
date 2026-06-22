"""Exception hierarchy for vulnscan.

All library-raised errors derive from :class:`VulnScanError` so callers (the CLI)
can distinguish expected, user-facing failures from unexpected crashes.
"""
from __future__ import annotations


class VulnScanError(Exception):
    """Base class for all vulnscan errors."""


class AuthorizationError(VulnScanError):
    """Raised when an authorization precondition for scanning is not satisfied.

    The engine refuses to run unless authorization is explicitly confirmed; this
    is the hard safety gate of the tool.
    """


class ScopeError(VulnScanError):
    """Raised for malformed scope files or scope-resolution failures."""


class ConfigError(VulnScanError):
    """Raised for invalid CLI/configuration combinations."""


class ModuleLoadError(VulnScanError):
    """Raised when a scanner module cannot be imported or instantiated."""
