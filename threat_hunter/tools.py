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

# Retry configuration
_MAX_RETRIES = 3
_RETRY_DELAY_SECONDS = 0.5
_REQUEST_TIMEOUT_SECONDS = 5.0


class VirusTotalAPIError(Exception):
    """Raised when VirusTotal API call fails after retries."""
    pass


def virustotal_ip_check(ip: str, timeout: float = _REQUEST_TIMEOUT_SECONDS) -> Optional[ReputationResult]:
    """Mock VirusTotal API - returns a reputation score for an IP address.

    Uses a deterministic hash-based score so results are consistent across runs.
    Known-malicious IPs from the demo dataset always return high scores.
    Implements retry logic to handle transient network failures gracefully.

    This is a mock: the lookup itself is pure computation, so `timeout` bounds
    the whole call rather than a socket read. Retry backoff is what actually
    consumes the budget today -- a caller passing a short timeout gets fewer
    retries instead of the full `_MAX_RETRIES * _RETRY_DELAY_SECONDS` wait.

    Args:
        ip: IP address to check
        timeout: Total wall-clock budget in seconds for the lookup, including
            retry backoff (default: 5). Must be positive.

    Returns:
        ReputationResult if successful, None if the retries or the time budget
        are exhausted
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    deadline = time.monotonic() + timeout

    for attempt in range(1, _MAX_RETRIES + 1):
        if time.monotonic() >= deadline:
            logger.error(
                "[VirusTotal API] Timed out checking IP %s after %.3fs budget (%d/%d attempts made)",
                ip, timeout, attempt - 1, _MAX_RETRIES,
            )
            return None

        try:
            logger.info("[VirusTotal API] Checking reputation for IP: %s (attempt %d/%d)", ip, attempt, _MAX_RETRIES)

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

            result = ReputationResult(ip=ip, score=score, verdict=verdict, details=details)
            logger.info("[VirusTotal API] Result: %s (score=%d)", verdict.value, score)
            return result

        except Exception as e:
            logger.warning("[VirusTotal API] Attempt %d failed: %s", attempt, str(e))
            if attempt >= _MAX_RETRIES:
                logger.error("[VirusTotal API] Failed to check IP %s after %d retries", ip, _MAX_RETRIES)
                return None
            # Never sleep past the deadline; the check at the top of the next
            # iteration turns an exhausted budget into a timeout.
            time.sleep(min(_RETRY_DELAY_SECONDS, max(0.0, deadline - time.monotonic())))

    return None
