"""LogIngestor - reads and parses JSON log files containing SIEM alerts."""

import json
import logging
from pathlib import Path
from signal import signal, SIGALRM, alarm

from .models import Alert

logger = logging.getLogger(__name__)


class LogIngestor:
    """Reads a local JSON log file and yields validated Alert objects."""

    INGEST_TIMEOUT_SECONDS = 300

    def __init__(self, filepath: str | Path) -> None:
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

    def _timeout_handler(self, signum, frame):
        raise TimeoutError(
            f"Alert ingestion exceeded {self.INGEST_TIMEOUT_SECONDS}s timeout"
        )

    def ingest(self) -> list[Alert]:
        """Parse the JSON log file and return a list of validated alerts."""
        logger.info("Ingesting alerts from %s", self.filepath)
        
        signal(SIGALRM, self._timeout_handler)
        alarm(self.INGEST_TIMEOUT_SECONDS)
        
        try:
            try:
                raw = json.loads(self.filepath.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in log file {self.filepath}: {exc}") from exc
            except TimeoutError as exc:
                raise TimeoutError(f"Reading log file {self.filepath} timed out: {exc}") from exc

            if not isinstance(raw, list):
                raise ValueError(f"Expected a JSON array in {self.filepath}, got {type(raw).__name__}")

            alerts: list[Alert] = []
            for entry in raw:
                try:
                    alert = Alert.model_validate(entry)
                    alerts.append(alert)
                except Exception as exc:
                    logger.warning("Skipping malformed alert entry: %s -- %s", entry, exc)

            logger.info("Ingested %d alerts", len(alerts))
            return alerts
        finally:
            alarm(0)
