"""Regression tests for timeout handling in `ThreatHunterAgent`.

A prior version of `agent.py` defined its own `TimeoutError` subclassing
`Exception` and used it in `except TimeoutError` clauses. Since
`LogIngestor.ingest()` raises the *builtin* `TimeoutError` (which subclasses
`OSError`, not `Exception` via that shadowed name), the shadowing class made
`except TimeoutError` in `agent.py` blind to genuine ingestion timeouts: they
fell through to the generic `except Exception` branch and were reported as a
plain ingestion error with a full traceback instead of a timeout.
"""

from pathlib import Path

import pytest

from threat_hunter.agent import ThreatHunterAgent

SAMPLE_ALERTS = Path(__file__).resolve().parent.parent / "sample_alerts.json"


def test_builtin_ingest_timeout_is_reported_as_timeout(monkeypatch, capsys):
    """A real `TimeoutError` from `LogIngestor.ingest()` must take the timeout branch."""
    agent = ThreatHunterAgent(str(SAMPLE_ALERTS))

    def fake_ingest():
        raise TimeoutError("Alert ingestion exceeded 300s timeout")

    monkeypatch.setattr(agent.ingestor, "ingest", fake_ingest)

    results = agent.run()

    assert results == []
    out = capsys.readouterr().out
    assert "Failed to load alerts within timeout" in out
    assert "Failed to load alerts" not in out.replace("Failed to load alerts within timeout", "")


def test_check_reputation_passes_configured_timeout_through(monkeypatch):
    """The per-call VirusTotal budget must come from the shared `virustotal_ip_check` timeout, not a second alarm."""
    agent = ThreatHunterAgent(str(SAMPLE_ALERTS), timeout=7)

    captured = {}

    def fake_check(ip, timeout=None):
        captured["ip"] = ip
        captured["timeout"] = timeout
        return None

    monkeypatch.setattr("threat_hunter.agent.virustotal_ip_check", fake_check)

    result = agent._step_check_reputation("203.0.113.42")

    assert result is None
    assert captured == {"ip": "203.0.113.42", "timeout": 7}
