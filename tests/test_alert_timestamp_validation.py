"""Regression tests for `Alert.timestamp` validation.

A custom `field_validator` was briefly added here to "enforce timestamp
parsing and non-null on alert ingestion," but pydantic v2 already rejects
null/unparseable timestamps on a bare `datetime` field -- the validator
added no fail-fast behavior that wasn't already there. It did, however,
narrow what's accepted: it rejected Unix epoch seconds (int/float), which
pydantic's lax mode parses natively and which is a common SIEM export
format. These tests pin the behavior that regressed and the behavior that
was never actually at risk.
"""

import pytest
from pydantic import ValidationError

from threat_hunter.models import Alert

_BASE_FIELDS = {
    "id": "ALERT-001",
    "severity": "HIGH",
    "source": "IDS",
    "message": "test",
}


def test_accepts_epoch_seconds_timestamp():
    """Unix epoch seconds (a common SIEM export format) must still validate."""
    alert = Alert(timestamp=1700000000, **_BASE_FIELDS)
    assert alert.timestamp.year == 2023


def test_accepts_iso_string_with_z_suffix():
    alert = Alert(timestamp="2026-02-16T08:23:11Z", **_BASE_FIELDS)
    assert alert.timestamp.isoformat() == "2026-02-16T08:23:11+00:00"


def test_rejects_null_timestamp():
    with pytest.raises(ValidationError):
        Alert(timestamp=None, **_BASE_FIELDS)


def test_rejects_unparseable_timestamp_string():
    with pytest.raises(ValidationError):
        Alert(timestamp="not-a-date", **_BASE_FIELDS)
