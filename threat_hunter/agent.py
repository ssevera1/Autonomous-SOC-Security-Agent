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
        """Step 1: Extract and validate the first IP address from the alert message."""
        for match in _IP_PATTERN.finditer(alert.message):
            candidate = match.group()
            try:
                ipaddress.ip_address(candidate)
                print(f"  [EXTRACT]  Found IP: {candidate}")
                return candidate
            except ValueError:
                continue
        print("  [EXTRACT]  No valid IP address found -- skipping alert.")
        return None

    def _step_check_reputation(self, ip: str) -> ReputationResult:
        """Step 2: Check IP reputation via threat intelligence."""
        print(f"  [DECIDE]   Checking IP reputation via VirusTotal...")
        result = virustotal_ip_check(ip)
        print(f"  [ANALYZE]  Verdict: {result.verdict.value} (score: {result.score}/100)")
        print(f"             {result.details}")
        return result

    def _step_remediate(self, ip: str, verdict: Verdict) -> str:
        """Step 3: Take action based on verdict, requesting human approval for destructive actions."""
        if verdict == Verdict.MALICIOUS:
            print(f"  [ACTION]   Threat confirmed -- remediation required.")
            blocked = request_remediation(ip)
            return "BLOCKED" if blocked else "DECLINED"
        elif verdict == Verdict.SUSPICIOUS:
            print(f"  [ACTION]   Suspicious activity -- flagged for analyst review.")
            return "FLAGGED"
        else:
            print(f"  [ACTION]   No threat detected -- no action needed.")
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
        print(f"\n  Loaded {len(alerts)} alerts. Beginning reasoning loop...\n")

        for alert in alerts:
            print(_SEPARATOR)
            print(f"  ALERT {alert.id}  |  {alert.severity.value}  |  {alert.source}")
            print(f"  {alert.message}")
            print("-" * 60)

            if _SEVERITY_ORDER[alert.severity] < _SEVERITY_ORDER[self.min_severity]:
                print(f"  [SKIP]     Severity below {self.min_severity.value} threshold.")
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
        print(f"  {'-'*10:<12} {'-'*8:<10} {'-'*16:<18} {'-'*10:<12} {'-'*6:<8} {'-'*10}")
        for r in self.results:
            print(
                f"  {r.alert_id:<12} "
                f"{r.severity.value:<10} "
                f"{r.ip or 'N/A':<18} "
                f"{r.verdict.value if r.verdict else 'N/A':<12} "
                f"{str(r.score) if r.score is not None else '-':<8} "
                f"{r.action}"
            )
        print(_SEPARATOR)
        print()
