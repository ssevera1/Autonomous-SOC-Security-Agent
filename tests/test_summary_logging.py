"""Regression tests for the action-count audit line emitted by the summary step."""

import logging
from pathlib import Path

import pytest

from threat_hunter.agent import ThreatHunterAgent
from threat_hunter.models import AnalysisResult, Severity, Verdict

# Must stay in sync with the formatter configured in main.py.
MAIN_LOG_FORMAT = "%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s"

SAMPLE_ALERTS = Path(__file__).resolve().parent.parent / "sample_alerts.json"


def _result(alert_id: str, action: str) -> AnalysisResult:
    return AnalysisResult(
        alert_id=alert_id,
        severity=Severity.HIGH,
        ip="203.0.113.10",
        verdict=Verdict.MALICIOUS,
        score=90,
        action=action,
    )


class _RecordCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def summary_records(capsys: pytest.CaptureFixture[str]) -> list[logging.LogRecord]:
    agent = ThreatHunterAgent(str(SAMPLE_ALERTS))
    agent.results = [
        _result("A-1", "BLOCKED"),
        _result("A-2", "DECLINED"),
        _result("A-3", "DECLINED"),
        _result("A-4", "FLAGGED"),
        _result("A-5", "NO_ACTION"),
        _result("A-6", "SKIPPED"),
        _result("A-7", "ERROR"),
    ]

    handler = _RecordCapture()
    logger = logging.getLogger("threat_hunter.agent")
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        agent._validate_and_print_summary()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    capsys.readouterr()
    return handler.records


def _action_counts_record(records: list[logging.LogRecord]) -> logging.LogRecord:
    matches = [r for r in records if r.getMessage().startswith("action_counts")]
    assert len(matches) == 1, f"expected one action_counts record, got {len(matches)}"
    return matches[0]


def test_action_counts_survive_the_plain_text_formatter(
    summary_records: list[logging.LogRecord],
) -> None:
    """Every count must appear in the rendered line, not only as `extra` attributes.

    main.py configures a format string that references only asctime/name/levelname/
    message, so counts attached via `extra=` alone are discarded before they reach
    threat_hunter.log.
    """
    record = _action_counts_record(summary_records)
    rendered = logging.Formatter(MAIN_LOG_FORMAT).format(record)

    for expected in (
        "blocked=1",
        "declined=2",
        "flagged=1",
        "no_action=1",
        "skipped=1",
        "error=1",
    ):
        assert expected in rendered, f"{expected!r} missing from log line: {rendered!r}"


def test_action_counts_also_attached_as_record_attributes(
    summary_records: list[logging.LogRecord],
) -> None:
    """Structured formatters can still read the counts off the record."""
    record = _action_counts_record(summary_records)

    assert record.blocked == 1  # type: ignore[attr-defined]
    assert record.declined == 2  # type: ignore[attr-defined]
    assert record.flagged == 1  # type: ignore[attr-defined]
    assert record.no_action == 1  # type: ignore[attr-defined]
    assert record.skipped == 1  # type: ignore[attr-defined]
    assert record.error == 1  # type: ignore[attr-defined]


def test_summary_message_still_reports_processed_and_skipped(
    summary_records: list[logging.LogRecord],
) -> None:
    """processed_count excludes SKIPPED alerts; guards the reordered assignments."""
    messages = [r.getMessage() for r in summary_records]
    summary = next(m for m in messages if m.startswith("Analysis complete."))

    assert "Alerts: 7" in summary
    assert "Processed: 6" in summary
    assert "Skipped: 1" in summary
