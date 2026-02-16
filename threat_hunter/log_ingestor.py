"""LogIngestor - reads and parses JSON log files containing SIEM alerts."""

import json
import logging
from pathlib import Path

from .models import Alert

logger = logging.getLogger(__name__)


class LogIngestor:
    """Reads a local JSON log file and yields validated Alert objects."""

    def __init__(self, filepath: str | Path) -> None:
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

    def ingest(self) -> list[Alert]:
        """Parse the JSON log file and return a list of validated alerts."""
        logger.info("Ingesting alerts from %s", self.filepath)
        raw = json.loads(self.filepath.read_text(encoding="utf-8"))

        alerts: list[Alert] = []
        for entry in raw:
            try:
                alert = Alert.model_validate(entry)
                alerts.append(alert)
            except Exception as exc:
                logger.warning("Skipping malformed alert entry: %s — %s", entry, exc)

        logger.info("Ingested %d alerts", len(alerts))
        return alerts
