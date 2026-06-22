"""The authorization gate — the hard safety control of the scanner.

A scan is refused unless authorization is explicitly confirmed. There are two
inputs, both required when a scope file is used:

1. The operator passes ``--authorize`` on the CLI (an explicit acknowledgement
   that they hold written authorization for the targets).
2. The scope file declares ``authorization.authorized: true`` with an
   ``authorized_by`` value and an optional, enforced ``expires`` date.

For the convenience ``--target`` mode (no scope file), ``--authorize`` alone is
required and the source is recorded as the CLI operator.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Optional

from .exceptions import AuthorizationError


@dataclass
class Authorization:
    """Authorization metadata describing who approved the engagement and when."""

    authorized: bool = False
    authorized_by: str = ""
    engagement_id: str = ""
    date: str = ""
    expires: str = ""
    notes: str = ""

    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> "Authorization":
        data = data or {}
        return cls(
            authorized=bool(data.get("authorized", False)),
            authorized_by=str(data.get("authorized_by", "") or ""),
            engagement_id=str(data.get("engagement_id", "") or ""),
            date=str(data.get("date", "") or ""),
            expires=str(data.get("expires", "") or ""),
            notes=str(data.get("notes", "") or ""),
        )

    @classmethod
    def from_cli(cls) -> "Authorization":
        """Authorization object representing operator acknowledgement via ``--authorize``."""
        return cls(
            authorized=True,
            authorized_by="operator (CLI --authorize)",
            engagement_id="",
            notes="No scope-file engagement metadata supplied; --target convenience mode.",
        )

    def is_valid(self, today: Optional[date] = None) -> tuple[bool, str]:
        """Return ``(ok, reason)``. ``ok`` is True only if all checks pass."""
        if not self.authorized:
            return False, "scope file does not declare 'authorization.authorized: true'"
        if not self.authorized_by.strip():
            return False, "'authorization.authorized_by' is required (who approved this engagement?)"
        if self.expires:
            try:
                expires_on = date.fromisoformat(self.expires)
            except ValueError:
                return False, f"'authorization.expires' is not a valid ISO date: {self.expires!r}"
            current = today or date.today()
            if current > expires_on:
                return False, f"authorization expired on {self.expires}"
        return True, "authorized"

    def require(self, cli_authorize: bool, today: Optional[date] = None) -> None:
        """Raise :class:`AuthorizationError` unless scanning is permitted.

        Both the CLI ``--authorize`` flag and a valid authorization record are
        required. This is the single chokepoint the engine calls before any
        target is touched.
        """
        if not cli_authorize:
            raise AuthorizationError(
                "Refusing to scan: you must pass --authorize to confirm you hold "
                "explicit written authorization to test these targets."
            )
        ok, reason = self.is_valid(today)
        if not ok:
            raise AuthorizationError(f"Refusing to scan: {reason}.")

    def banner(self) -> str:
        """A short, human-readable authorization summary for the console banner."""
        lines = ["AUTHORIZED SCAN"]
        if self.authorized_by:
            lines.append(f"  Authorized by : {self.authorized_by}")
        if self.engagement_id:
            lines.append(f"  Engagement    : {self.engagement_id}")
        if self.date:
            lines.append(f"  Approved on   : {self.date}")
        if self.expires:
            lines.append(f"  Expires       : {self.expires}")
        return "\n".join(lines)
