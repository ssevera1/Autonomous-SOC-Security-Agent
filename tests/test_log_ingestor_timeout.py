"""Regression tests for the ingestion timeout in `LogIngestor.ingest()`.

A naive `signal.alarm()` timeout that fires while validating an entry gets
caught by the broad `except Exception` guarding malformed entries, logged as
a bogus "malformed entry" warning, and then the loop keeps running with no
alarm armed -- ingestion is unbounded anyway. These tests pin that the
timeout actually propagates, that arming/restoring the alarm doesn't leak
process-global state, and that ingestion still works when SIGALRM isn't
available.
"""

import json
import signal

import pytest

from threat_hunter.log_ingestor import LogIngestor
from threat_hunter.models import Alert


@pytest.fixture(autouse=True)
def _clear_lingering_alarm():
    yield
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)


def _write_log(tmp_path, entries):
    log_file = tmp_path / "alerts.json"
    log_file.write_text(json.dumps(entries))
    return log_file


def test_timeout_during_validation_propagates(tmp_path, monkeypatch, caplog):
    """A TimeoutError raised mid-loop must propagate, not be swallowed as a malformed entry."""
    log_file = _write_log(tmp_path, [{"id": "1"}, {"id": "2"}])

    def fake_validate(_entry):
        raise TimeoutError("Alert ingestion exceeded 300s timeout")

    monkeypatch.setattr(Alert, "model_validate", staticmethod(fake_validate))

    ingestor = LogIngestor(log_file)
    with pytest.raises(TimeoutError):
        ingestor.ingest()

    assert "malformed" not in caplog.text.lower()


def test_still_raises_malformed_warning_for_genuine_validation_errors(tmp_path, monkeypatch, caplog):
    """Narrowing the except clause must not stop real validation failures from being skipped."""
    log_file = _write_log(tmp_path, [{"id": "1"}])

    ingestor = LogIngestor(log_file)
    with caplog.at_level("WARNING"):
        alerts = ingestor.ingest()

    assert alerts == []
    assert "malformed" in caplog.text.lower()


def test_ingest_works_when_alarm_unsupported(tmp_path, monkeypatch):
    """When arming isn't safe (e.g. off the main thread), ingestion must still work."""
    monkeypatch.setattr("threat_hunter.log_ingestor._alarm_supported", lambda: False)

    calls = []
    monkeypatch.setattr(signal, "signal", lambda *a, **k: calls.append(("signal", a, k)))
    monkeypatch.setattr(signal, "alarm", lambda *a, **k: calls.append(("alarm", a, k)))

    log_file = _write_log(tmp_path, [
        {
            "id": "1",
            "timestamp": "2024-01-01T00:00:00",
            "severity": "LOW",
            "source": "test",
            "message": "hello",
        }
    ])

    alerts = LogIngestor(log_file).ingest()

    assert len(alerts) == 1
    assert calls == []


def test_alarm_disposition_is_restored_after_call(tmp_path):
    """`ingest()` is a library call; it must not leave its handler installed forever."""
    log_file = _write_log(tmp_path, [])

    previous_handler = signal.getsignal(signal.SIGALRM)
    LogIngestor(log_file).ingest()

    assert signal.getsignal(signal.SIGALRM) is previous_handler


def test_pre_existing_alarm_is_restored(tmp_path):
    """Arming the ingestion timeout must not permanently cancel an unrelated pending alarm."""
    log_file = _write_log(tmp_path, [])

    signal.alarm(10)
    try:
        LogIngestor(log_file).ingest()
        remaining = signal.alarm(0)
        assert remaining > 0, "pre-existing alarm was clobbered instead of restored"
    finally:
        signal.alarm(0)
