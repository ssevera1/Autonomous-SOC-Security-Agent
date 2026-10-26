"""Pydantic models for alerts and threat intelligence responses."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    CLEAN = "Clean"


class Alert(BaseModel):
    """A single SIEM alert ingested from the log file."""

    id: str
    timestamp: datetime
    severity: Severity
    source: str
    message: str

    @field_validator('timestamp', mode='before')
    @classmethod
    def validate_timestamp(cls, v):
        if v is None:
            raise ValueError('timestamp cannot be null')
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except (ValueError, TypeError) as e:
                raise ValueError(f'timestamp must be parseable as ISO 8601 datetime: {e}')
        raise ValueError('timestamp must be a datetime object or ISO 8601 string')


class ReputationResult(BaseModel):
    """Result returned by the VirusTotal API mock."""

    ip: str
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    details: str


class AnalysisResult(BaseModel):
    """The outcome of processing a single alert through the reasoning loop."""

    alert_id: str
    severity: Severity
    ip: str | None = None
    verdict: Verdict | None = None
    score: int | None = None
    action: str  # BLOCKED, DECLINED, FLAGGED, NO_ACTION, SKIPPED
