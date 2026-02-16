"""Pydantic models for alerts and threat intelligence responses."""

from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    MALICIOUS = "Malicious"
    CLEAN = "Clean"


class Alert(BaseModel):
    """A single SIEM alert ingested from the log file."""

    id: str
    timestamp: str
    severity: Severity
    source: str
    message: str


class ReputationResult(BaseModel):
    """Result returned by the VirusTotal API mock."""

    ip: str
    score: int  # 0-100, higher = more suspicious
    verdict: Verdict
    details: str
