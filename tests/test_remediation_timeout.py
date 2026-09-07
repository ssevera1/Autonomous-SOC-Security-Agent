"""Regression tests for the approval-prompt timeout in `request_remediation()`.

An unanswered human-in-the-loop prompt must not hang the agent forever, but a
naive `signal.alarm()` timeout can (a) leave stale keystrokes in the tty
buffer to bleed into the *next* alert's prompt, (b) permanently disable the
prompt if arming the alarm fails (off-thread, or no SIGALRM support), and (c)
clobber a pre-existing alarm in the process. These tests pin all three
contracts, plus that a normal Y/N answer still works with the alarm armed.
"""

import signal

import pytest

from threat_hunter import remediation


@pytest.fixture(autouse=True)
def _clear_lingering_alarm():
    """Belt-and-suspenders: never let a failed test leave a real alarm armed."""
    yield
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)


def test_timeout_denies_without_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    """The alarm firing must return False promptly instead of hanging."""
    blocked: list[str] = []
    monkeypatch.setattr(remediation, "block_ip", lambda ip: blocked.append(ip))

    def slow_input(_prompt: str) -> str:
        # Never returns before the (short) timeout fires.
        import time

        time.sleep(1)
        return "Y"

    monkeypatch.setattr("builtins.input", slow_input)
    monkeypatch.setattr(remediation, "_flush_pending_stdin", lambda: None)

    result = remediation.request_remediation("203.0.113.42", timeout=0.05)

    assert result is False
    assert blocked == []


def test_timeout_flushes_pending_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timed-out prompt must discard buffered input so it can't answer the next alert."""
    flushed = []
    monkeypatch.setattr(remediation, "_flush_pending_stdin", lambda: flushed.append(True))

    def slow_input(_prompt: str) -> str:
        import time

        time.sleep(1)
        return "Y"

    monkeypatch.setattr("builtins.input", slow_input)

    remediation.request_remediation("203.0.113.42", timeout=0.05)

    assert flushed == [True]


def test_normal_response_still_works_with_alarm_armed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A prompt answered well within the budget must behave exactly as before."""
    blocked: list[str] = []
    monkeypatch.setattr(remediation, "block_ip", lambda ip: blocked.append(ip))
    monkeypatch.setattr("builtins.input", lambda _prompt: "Y")

    result = remediation.request_remediation("203.0.113.42", timeout=5)

    assert result is True
    assert blocked == ["203.0.113.42"]


def test_decline_still_works_with_alarm_armed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "N")

    result = remediation.request_remediation("203.0.113.42", timeout=5)

    assert result is False


def test_alarm_unavailable_falls_back_to_plain_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """When arming isn't safe (e.g. off the main thread), the prompt must still work."""
    monkeypatch.setattr(remediation, "_alarm_supported", lambda: False)
    monkeypatch.setattr("builtins.input", lambda _prompt: "Y")

    alarm_calls = []
    monkeypatch.setattr(signal, "signal", lambda *a, **k: alarm_calls.append(("signal", a, k)))
    monkeypatch.setattr(signal, "setitimer", lambda *a, **k: alarm_calls.append(("setitimer", a, k)))

    result = remediation.request_remediation("203.0.113.42", timeout=5)

    assert result is True
    assert alarm_calls == []


def test_alarm_disposition_is_restored_after_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """`request_remediation` is a library call; it must not leave its handler installed forever."""
    monkeypatch.setattr("builtins.input", lambda _prompt: "Y")

    previous_handler = signal.getsignal(signal.SIGALRM)
    remediation.request_remediation("203.0.113.42", timeout=5)

    assert signal.getsignal(signal.SIGALRM) is previous_handler


def test_pre_existing_alarm_is_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Arming the approval timeout must not permanently cancel an unrelated pending alarm."""
    monkeypatch.setattr("builtins.input", lambda _prompt: "Y")

    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        remediation.request_remediation("203.0.113.42", timeout=5)
        remaining, _interval = signal.getitimer(signal.ITIMER_REAL)
        assert remaining > 0, "pre-existing alarm was clobbered instead of restored"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
