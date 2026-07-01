"""Core reasoning loop for the Autonomous Threat Hunter agent."""

import ipaddress
import logging
import re

from .log_ingestor import LogIngestor
from .models import Alert, AnalysisResult, ReputationResult, Severity, Verdict
from .remediation import request_remediation
from .tools import virustotal_ip_check

logger = logging.getLogger(__name__)

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SEPARATOR = "=" * 60

_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class ThreatHunterAgent:
    """Autonomous agent that ingests alerts, reasons about threats, and
    recommends remediation with human-in-the-loop approval."""

    def __init__(self, log_file: str, min_severity: Severity = Severity.LOW) -> None:
        self.ingestor = LogIngestor(log_file)
        self.min_severity = min_severity
        self.results: list[AnalysisResult] = []

    # ----- reasoning steps -----

    def _step_extract_ip(self, alert: Alert) -> str | None:
        """Step 1: Extract and validate the first public IP address from the alert message."""
        for match in _IP_PATTERN.finditer(alert.message):
            candidate = match.group()
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                logger.debug("Invalid IP format: %s", candidate)
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                print(f"  [EXTRACT]  Skipping non-public IP: {candidate}")
                logger.debug("Skipping non-public IP %s (private=%s, loopback=%s, link_local=%s, reserved=%s)",
                            candidate, addr.is_private, addr.is_loopback, addr.is_link_local, addr.is_reserved)
                continue
            print(f"  [EXTRACT]  Found IP: {candidate}")
            logger.info("Extracted IP from alert %s: %s", alert.id, candidate)
            return candidate
        print("  [EXTRACT]  No valid public IP address found -- skipping alert.")
        logger.debug("No valid public IP found in alert %s message: %s", alert.id, alert.message)
        return None

    def _step_check_reputation(self, ip: str) -> ReputationResult:
        """Step 2: Check IP reputation via threat intelligence."""
        print(f"  [DECIDE]   Checking IP reputation via VirusTotal...")
        logger.info("Checking reputation for IP: %s", ip)
        result = virustotal_ip_check(ip)
        print(f"  [ANALYZE]  Verdict: {result.verdict.value} (score: {result.score}/100)")
        print(f"             {result.details}")
        logger.info("IP %s reputation check: verdict=%s score=%d", ip, result.verdict.value, result.score)
        return result

    def _step_remediate(self, ip: str, verdict: Verdict) -> str:
        """Step 3: Take action based on verdict, requesting human approval for destructive actions."""
        if verdict == Verdict.MALICIOUS:
            print(f"  [ACTION]   Threat confirmed -- remediation required.")
            logger.warning("Malicious verdict for IP %s - requesting remediation", ip)
            blocked = request_remediation(ip)
            return "BLOCKED" if blocked else "DECLINED"
        elif verdict == Verdict.SUSPICIOUS:
            print(f"  [ACTION]   Suspicious activity -- flagged for analyst review.")
            logger.warning("Suspicious verdict for IP %s - flagged for review", ip)
            return "FLAGGED"
        else:
            print(f"  [ACTION]   No threat detected -- no action needed.")
            logger.info("Clean verdict for IP %s - no action taken", ip)
            return "NO_ACTION"

    # ----- main loop -----

    def run(self) -> list[AnalysisResult]:
        """Execute the full reasoning loop across all ingested alerts."""
        print()
        print(_SEPARATOR)
        print("  AUTONOMOUS THREAT HUNTER -- Starting Analysis")
        if self.min_severity != Severity.LOW:
            print(f"  Minimum severity threshold: {self.min_severity.value}")
        print(_SEPARATOR)

        alerts = self.ingestor.ingest()
        if not alerts:
            logger.warning("No alerts loaded from log file")
            print(f"\n  [WARN] No alerts loaded. Exiting.\n")
            return []

        print(f"\n  Loaded {len(alerts)} alerts. Beginning reasoning loop...\n")

        for alert in alerts:
            print(_SEPARATOR)
            print(f"  ALERT {alert.id}  |  {alert.severity.value}  |  {alert.source}")
            print(f"  {alert.message}")
            print("-" * 60)

            if _SEVERITY_ORDER[alert.severity] < _SEVERITY_ORDER[self.min_severity]:
                print(f"  [SKIP]     Severity below {self.min_severity.value} threshold.")
                logger.debug("Skipping alert %s: severity %s below threshold %s",
                            alert.id, alert.severity.value, self.min_severity.value)
                self.results.append(AnalysisResult(alert_id=alert.id, severity=alert.severity, action="SKIPPED"))
                print()
                continue

            # Step 1 - Extract
            ip = self._step_extract_ip(alert)
            if ip is None:
                self.results.append(AnalysisResult(alert_id=alert.id, severity=alert.severity, action="SKIPPED"))
                print()
                continue

            # Step 2 - Analyze
            reputation = self._step_check_reputation(ip)

            # Step 3 - Act
            action = self._step_remediate(ip, reputation.verdict)

            self.results.append(AnalysisResult(
                alert_id=alert.id,
                severity=alert.severity,
                ip=ip,
                verdict=reputation.verdict,
                score=reputation.score,
                action=action,
            ))
            print()

        self._print_summary()
        return self.results

    def _print_summary(self) -> None:
        """Print a final summary table of all actions taken."""
        print(_SEPARATOR)
        print("  SUMMARY")
        print(_SEPARATOR)
        print(f"  {'Alert':<12} {'Severity':<10} {'IP':<18} {'Verdict':<12} {'Score':<8} {'Action'}")
        print(f"  {'-'*10:<12} {'-'*8:<10} {'-'*16:<18} {'-'*10:<12} {'-'*6:<8} {'-'*15}")

        for result in self.results:
            ip_str = result.ip or "—"
            verdict_str = result.verdict.value if result.verdict else "—"
            score_str = str(result.score) if result.score is not None else "—"
            print(f"  {result.alert_id:<12} {result.severity.value:<10} {ip_str:<18} {verdict_str:<12} {score_str:<8} {result.action}")

        print(_SEPARATOR)
        logger.info("Analysis complete. Total alerts processed: %d", len(self.results))
