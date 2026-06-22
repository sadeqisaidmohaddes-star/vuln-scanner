"""Tests for the authorization gate — the hard safety control of the scanner.

These tests exercise :class:`vulnscan.core.authorization.Authorization` directly.
All date-dependent checks pass a fixed ``today`` (2026-06-13) so the suite is
deterministic and never depends on the real clock.
"""
from __future__ import annotations

import datetime

import pytest

from vulnscan.core.authorization import Authorization
from vulnscan.core.exceptions import AuthorizationError

# A fixed "today" used everywhere so expiry checks are time-independent.
TODAY = datetime.date(2026, 6, 13)


def _valid_record() -> Authorization:
    """A fully valid authorization record (no expiry constraint failure)."""
    return Authorization(
        authorized=True,
        authorized_by="Jane Operator",
        engagement_id="ENG-2026-001",
        date="2026-06-01",
        expires="2026-12-31",
        notes="written authorization on file",
    )


# --- is_valid -------------------------------------------------------------


def test_is_valid_false_when_not_authorized():
    rec = Authorization(authorized=False, authorized_by="Jane Operator")
    ok, reason = rec.is_valid(today=TODAY)
    assert ok is False
    assert "authorized" in reason


def test_is_valid_false_when_authorized_by_empty():
    rec = Authorization(authorized=True, authorized_by="")
    ok, reason = rec.is_valid(today=TODAY)
    assert ok is False
    assert "authorized_by" in reason


def test_is_valid_false_when_authorized_by_whitespace():
    # ``authorized_by`` is stripped, so whitespace-only must also be rejected.
    rec = Authorization(authorized=True, authorized_by="   ")
    ok, reason = rec.is_valid(today=TODAY)
    assert ok is False
    assert "authorized_by" in reason


def test_is_valid_false_when_expired():
    rec = Authorization(
        authorized=True,
        authorized_by="Jane Operator",
        expires="2026-06-12",  # one day before the fixed today
    )
    ok, reason = rec.is_valid(today=TODAY)
    assert ok is False
    assert "expired" in reason
    assert "2026-06-12" in reason


def test_is_valid_true_for_valid_record():
    ok, reason = _valid_record().is_valid(today=TODAY)
    assert ok is True
    assert reason == "authorized"


def test_is_valid_true_when_expires_is_today():
    # The check is ``current > expires_on``; expiring exactly today is still valid.
    rec = Authorization(
        authorized=True,
        authorized_by="Jane Operator",
        expires="2026-06-13",
    )
    ok, reason = rec.is_valid(today=TODAY)
    assert ok is True
    assert reason == "authorized"


# --- require --------------------------------------------------------------


def test_require_without_cli_authorize_raises_even_for_valid_record():
    rec = _valid_record()
    with pytest.raises(AuthorizationError) as excinfo:
        rec.require(cli_authorize=False, today=TODAY)
    assert "--authorize" in str(excinfo.value)


def test_require_with_invalid_record_raises():
    # CLI flag is set, but the record itself is invalid (not authorized).
    rec = Authorization(authorized=False, authorized_by="Jane Operator")
    with pytest.raises(AuthorizationError):
        rec.require(cli_authorize=True, today=TODAY)


def test_require_with_expired_record_raises():
    rec = Authorization(
        authorized=True,
        authorized_by="Jane Operator",
        expires="2026-06-12",
    )
    with pytest.raises(AuthorizationError) as excinfo:
        rec.require(cli_authorize=True, today=TODAY)
    assert "expired" in str(excinfo.value)


def test_require_with_valid_record_does_not_raise():
    # Both the CLI flag and a valid record present: must not raise.
    _valid_record().require(cli_authorize=True, today=TODAY)


# --- banner ---------------------------------------------------------------


def test_banner_includes_authorized_by_and_engagement_id():
    banner = _valid_record().banner()
    assert "Jane Operator" in banner
    assert "ENG-2026-001" in banner
    assert "AUTHORIZED SCAN" in banner
