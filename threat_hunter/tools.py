"""Mock threat intelligence tools (VirusTotal API, etc.)."""

import hashlib
import logging

from .models import ReputationResult, Verdict

logger = logging.getLogger(__name__)

# IPs explicitly marked malicious for demo purposes
_KNOWN_MALICIOUS = {
    "203.0.113.42",
    "198.51.100.23",
    "45.33.32.156",
}


def virustotal_ip_check(ip: str) -> ReputationResult:
    """Mock VirusTotal API - returns a reputation score for an IP address.

    Uses a deterministic hash-based score so results are consistent across runs.
    Known-malicious IPs from the demo dataset always return high scores.
    """
    logger.info("[VirusTotal API] Checking reputation for IP: %s", ip)

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
