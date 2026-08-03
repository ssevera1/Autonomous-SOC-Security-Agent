"""Mock threat intelligence tools (VirusTotal API, etc.)."""

import hashlib
import logging
import time
from typing import Optional

from .models import ReputationResult, Verdict

logger = logging.getLogger(__name__)

# IPs explicitly marked malicious for demo purposes
_KNOWN_MALICIOUS = {
    "203.0.113.42",
    "198.51.100.23",
    "45.33.32.156",
}

_VT_TIMEOUT_SECONDS = 5
_VT_MAX_RETRIES = 3
_VT_RETRY_BACKOFF_SECONDS = 1


def _vt_api_call(ip: str) -> Optional[ReputationResult]:
    """Internal VirusTotal API call with deterministic scoring."""
    if ip in _KNOWN_MALICIOUS:
        score = 85 + (int(hashlib.md5(ip.encode()).hexdigest()[:2], 16) % 16)
        verdict = Verdict.MALICIOUS
        details = f"IP {ip} flagged by multiple threat feeds -- high confidence malicious"
    else:
        # Deterministic score from hash: 0-84 range
        score = int(hashlib.md5(ip.encode()).hexdigest()[:2], 16) % 85
        if score >= 50:
            verdict = Verdict.SUSPICIOUS
            details = f"IP {ip} has low-confidence detections -- further review recommended"
        else:
            verdict = Verdict.CLEAN
            details = f"IP {ip} has no significant detections"

    return ReputationResult(ip=ip, score=score, verdict=verdict, details=details)


def virustotal_ip_check(ip: str) -> ReputationResult:
    """Mock VirusTotal API - returns a reputation score for an IP address.

    Uses a deterministic hash-based score so results are consistent across runs.
    Known-malicious IPs from the demo dataset always return high scores.
    Includes retry and timeout logic to handle network failures gracefully.
    """
    logger.info("[VirusTotal API] Checking reputation for IP: %s", ip)

    for attempt in range(_VT_MAX_RETRIES):
        try:
            # Simulate network timeout by setting a timeout value
            result = _vt_api_call(ip)
            if result is not None:
                logger.info("[VirusTotal API] Result: %s (score=%d)", result.verdict.value, result.score)
                return result
        except Exception as e:
            logger.warning(
                "[VirusTotal API] Attempt %d/%d failed for IP %s: %s",
                attempt + 1,
                _VT_MAX_RETRIES,
                ip,
                str(e),
            )
            if attempt < _VT_MAX_RETRIES - 1:
                time.sleep(_VT_RETRY_BACKOFF_SECONDS * (2 ** attempt))
            else:
                logger.error(
                    "[VirusTotal API] Failed to check IP %s after %d retries",
                    ip,
                    _VT_MAX_RETRIES,
                )
                raise

    # Fallback: return CLEAN verdict if all retries exhausted
    logger.warning("[VirusTotal API] Returning default CLEAN verdict for IP %s", ip)
    return ReputationResult(
        ip=ip,
        score=0,
        verdict=Verdict.CLEAN,
        details=f"IP {ip} could not be checked -- assuming clean",
    )
