"""Regression tests for the `timeout` budget on `whois_lookup()` and `geoip_lookup()`.

Both are mocks with no socket underneath them, so `timeout` cannot mean
"socket read deadline". It means "total wall-clock budget for the call,
including retry backoff": a caller with a short budget gets fewer retries
instead of the full `_MAX_RETRIES * _RETRY_DELAY_SECONDS` wait. These tests
pin that contract so the parameter cannot quietly go back to being decorative
-- before the `_lookup_whois_registrar`/`_lookup_geoip_location` seams
existed, the try bodies could never raise, so the retry/timeout paths below
were unreachable dead code.
"""

import logging
import time

import pytest

from threat_hunter import tools


@pytest.fixture
def failing_whois(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    attempts: list[int] = []

    def boom(domain: str) -> str:
        attempts.append(1)
        raise RuntimeError("simulated upstream failure")

    monkeypatch.setattr(tools, "_lookup_whois_registrar", boom)
    return attempts


@pytest.fixture
def failing_geoip(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    attempts: list[int] = []

    def boom(ip: str) -> str:
        attempts.append(1)
        raise RuntimeError("simulated upstream failure")

    monkeypatch.setattr(tools, "_lookup_geoip_location", boom)
    return attempts


@pytest.mark.parametrize("bad_timeout", [0, 0.0, -1, -0.5])
def test_whois_non_positive_timeout_is_rejected(bad_timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        tools.whois_lookup("example.com", timeout=bad_timeout)


@pytest.mark.parametrize("bad_timeout", [0, 0.0, -1, -0.5])
def test_geoip_non_positive_timeout_is_rejected(bad_timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        tools.geoip_lookup("8.8.8.8", timeout=bad_timeout)


def test_whois_happy_path_is_unchanged_by_the_deadline_check() -> None:
    result = tools.whois_lookup("example.com")
    assert result == "Mock Registrar for example.com"


def test_geoip_happy_path_is_unchanged_by_the_deadline_check() -> None:
    result = tools.geoip_lookup("8.8.8.8")
    assert result == "Mock Location for 8.8.8.8"


def test_whois_short_budget_gives_up_before_exhausting_the_retries(
    failing_whois: list[int],
    caplog: pytest.LogCaptureFixture,
) -> None:
    budget = 0.05
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    started = time.monotonic()
    result = tools.whois_lookup("example.com", timeout=budget)
    elapsed = time.monotonic() - started

    assert result is None
    assert len(failing_whois) < tools._MAX_RETRIES, "budget was ignored; all retries ran"
    assert elapsed < (tools._MAX_RETRIES - 1) * tools._RETRY_DELAY_SECONDS
    assert any("Timed out looking up domain" in r.getMessage() for r in caplog.records)


def test_geoip_short_budget_gives_up_before_exhausting_the_retries(
    failing_geoip: list[int],
    caplog: pytest.LogCaptureFixture,
) -> None:
    budget = 0.05
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    started = time.monotonic()
    result = tools.geoip_lookup("8.8.8.8", timeout=budget)
    elapsed = time.monotonic() - started

    assert result is None
    assert len(failing_geoip) < tools._MAX_RETRIES, "budget was ignored; all retries ran"
    assert elapsed < (tools._MAX_RETRIES - 1) * tools._RETRY_DELAY_SECONDS
    assert any("Timed out looking up IP" in r.getMessage() for r in caplog.records)


def test_whois_generous_budget_still_uses_every_retry(
    failing_whois: list[int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    result = tools.whois_lookup("example.com", timeout=30)

    assert result is None
    assert len(failing_whois) == tools._MAX_RETRIES
    assert any("after 3 retries" in r.getMessage() for r in caplog.records)
    assert not any("Timed out" in r.getMessage() for r in caplog.records)


def test_geoip_generous_budget_still_uses_every_retry(
    failing_geoip: list[int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    result = tools.geoip_lookup("8.8.8.8", timeout=30)

    assert result is None
    assert len(failing_geoip) == tools._MAX_RETRIES
    assert any("after 3 retries" in r.getMessage() for r in caplog.records)
    assert not any("Timed out" in r.getMessage() for r in caplog.records)


def test_whois_retry_backoff_never_sleeps_past_the_deadline(
    failing_whois: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: slept.append(seconds))

    budget = 0.05
    tools.whois_lookup("example.com", timeout=budget)

    assert slept, "expected at least one backoff"
    assert all(0.0 <= s <= budget for s in slept), f"backoff overshot the budget: {slept}"


def test_geoip_retry_backoff_never_sleeps_past_the_deadline(
    failing_geoip: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: slept.append(seconds))

    budget = 0.05
    tools.geoip_lookup("8.8.8.8", timeout=budget)

    assert slept, "expected at least one backoff"
    assert all(0.0 <= s <= budget for s in slept), f"backoff overshot the budget: {slept}"
