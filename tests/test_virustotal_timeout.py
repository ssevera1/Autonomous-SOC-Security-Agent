"""Regression tests for the `timeout` budget on `virustotal_ip_check()`.

`virustotal_ip_check` is a mock with no socket underneath it, so `timeout`
cannot mean "socket read deadline". It means "total wall-clock budget for the
call, including retry backoff": a caller with a short budget gets fewer retries
instead of the full `_MAX_RETRIES * _RETRY_DELAY_SECONDS` wait. These tests pin
that contract so the parameter cannot quietly go back to being decorative.
"""

import logging
import time

import pytest

from threat_hunter import tools
from threat_hunter.models import Verdict


@pytest.fixture
def failing_lookup(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make every attempt fail, and record how many attempts were made.

    `ReputationResult` is constructed at the very end of the try body, so
    exploding there exercises the full attempt before the retry handler runs.
    """
    attempts: list[int] = []

    def boom(**kwargs: object) -> None:
        attempts.append(1)
        raise RuntimeError("simulated upstream failure")

    monkeypatch.setattr(tools, "ReputationResult", boom)
    return attempts


@pytest.mark.parametrize("bad_timeout", [0, 0.0, -1, -0.5])
def test_non_positive_timeout_is_rejected(bad_timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        tools.virustotal_ip_check("203.0.113.42", timeout=bad_timeout)


def test_happy_path_is_unchanged_by_the_deadline_check() -> None:
    """A normal call fits inside the default budget and still returns a verdict."""
    malicious = tools.virustotal_ip_check("203.0.113.42")
    assert malicious is not None
    assert malicious.verdict == Verdict.MALICIOUS

    benign = tools.virustotal_ip_check("8.8.8.8")
    assert benign is not None
    assert benign.verdict != Verdict.MALICIOUS


def test_short_budget_gives_up_before_exhausting_the_retries(
    failing_lookup: list[int],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The whole point of the parameter: a small budget must cut retries short.

    Without the deadline, a failing lookup always burns
    `_MAX_RETRIES` attempts and ~1s of backoff no matter what the caller asked for.
    """
    budget = 0.05
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    started = time.monotonic()
    result = tools.virustotal_ip_check("203.0.113.42", timeout=budget)
    elapsed = time.monotonic() - started

    assert result is None
    assert len(failing_lookup) < tools._MAX_RETRIES, "budget was ignored; all retries ran"
    # The backoff alone would have taken this long had the deadline not clamped it.
    assert elapsed < (tools._MAX_RETRIES - 1) * tools._RETRY_DELAY_SECONDS

    assert any("Timed out checking IP" in r.getMessage() for r in caplog.records)


def test_generous_budget_still_uses_every_retry(
    failing_lookup: list[int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The deadline must not cost the caller retries they had budget for."""
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)
    caplog.set_level(logging.ERROR, logger="threat_hunter.tools")

    result = tools.virustotal_ip_check("203.0.113.42", timeout=30)

    assert result is None
    assert len(failing_lookup) == tools._MAX_RETRIES
    assert any("after 3 retries" in r.getMessage() for r in caplog.records)
    assert not any("Timed out" in r.getMessage() for r in caplog.records)


def test_retry_backoff_never_sleeps_past_the_deadline(
    failing_lookup: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backoff is clamped to the remaining budget rather than overshooting it.

    Sleep is stubbed out, so the clock barely moves and every backoff sees
    roughly the full budget remaining -- what matters is that none of them is
    the unclamped `_RETRY_DELAY_SECONDS`.
    """
    slept: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: slept.append(seconds))

    budget = 0.05
    tools.virustotal_ip_check("203.0.113.42", timeout=budget)

    assert slept, "expected at least one backoff"
    assert all(0.0 <= s <= budget for s in slept), f"backoff overshot the budget: {slept}"
