"""Core reasoning loop for the Autonomous Threat Hunter agent."""

import ipaddress
import logging
import re
import sys

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
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                self._safe_print(f"  [EXTRACT]  Skipping non-public IP: {candidate}")
                continue
            self._safe_print(f"  [EXTRACT]  Found IP: {candidate}")
            return candidate
        self._safe_print("  [EXTRACT]  No valid public IP address found -- skipping alert.")
        return None

    def _step_check_reputation(self, ip: str) -> ReputationResult | None:
        """Step 2: Check IP reputation via threat intelligence."""
        self._safe_print(f"  [DECIDE]   Checking IP reputation via VirusTotal...")
        result = virustotal_ip_check(ip)
        if result is None:
            self._safe_print(f"  [ANALYZE]  VirusTotal check failed after retries -- cannot determine verdict.")
            return None
        self._safe_print(f"  [ANALYZE]  Verdict: {result.verdict.value} (score: {result.score}/100)")
        self._safe_print(f"             {result.details}")
        return result

    def _step_remediate(self, ip: str, verdict: Verdict) -> str:
        """Step 3: Take action based on verdict, requesting human approval for destructive actions."""
        if verdict == Verdict.MALICIOUS:
            self._safe_print(f"  [ACTION]   Threat confirmed -- remediation required.")
            try:
                blocked = request_remediation(ip)
                return "BLOCKED" if blocked else "DECLINED"
            except (EOFError, KeyboardInterrupt) as e:
                logger.error(f"Remediation prompt interrupted for IP {ip}: {type(e).__name__}")
                return "DECLINED"
        elif verdict == Verdict.SUSPICIOUS:
            self._safe_print(f"  [ACTION]   Suspicious activity -- flagged for analyst review.")
            return "FLAGGED"
        else:
            self._safe_print(f"  [ACTION]   No threat detected -- no action needed.")
            return "NO_ACTION"

    def _safe_print(self, message: str) -> None:
        """Print with error handling for interactive prompts."""
        try:
            print(message)
            sys.stdout.flush()
        except (EOFError, KeyboardInterrupt) as e:
            logger.error(f"Print operation interrupted during interactive prompt: {type(e).__name__}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error during print: {type(e).__name__}: {e}", exc_info=True)

    # ----- main loop -----

    def run(self) -> list[AnalysisResult]:
        """Execute the full reasoning loop across all ingested alerts."""
        self._safe_print("")
        self._safe_print(_SEPARATOR)
        self._safe_print("  AUTONOMOUS THREAT HUNTER -- Starting Analysis")
        if self.min_severity != Severity.LOW:
            self._safe_print(f"  Minimum severity threshold: {self.min_severity.value}")
        self._safe_print(_SEPARATOR)

        alerts = self.ingestor.ingest()
        self._safe_print(f"\n  Loaded {len(alerts)} alerts. Beginning reasoning loop...\n")

        for alert in alerts:
            self._safe_print(_SEPARATOR)
            self._safe_print(f"  ALERT {alert.id}  |  {alert.severity.value}  |  {alert.source}")
            self._safe_print(f"  {alert.message}")
            self._safe_print("-" * 60)

            if _SEVERITY_ORDER[alert.severity] < _SEVERITY_ORDER[self.min_severity]:
                self._safe_print(f"  [SKIP]     Severity below {self.min_severity.value} threshold.")
                self.results.append(AnalysisResult(alert_id=alert.id, severity=alert.severity, action="SKIPPED"))
                self._safe_print("")
                continue

            # Step 1 - Extract
            ip = self._step_extract_ip(alert)
            if ip is None:
                self.results.append(AnalysisResult(alert_id=alert.id, severity=alert.severity, action="SKIPPED"))
                self._safe_print("")
                continue

            # Step 2 - Analyze
            reputation = self._step_check_reputation(ip)
            if reputation is None:
                self.results.append(AnalysisResult(
                    alert_id=alert.id, severity=alert.severity, ip=ip, action="ERROR",
                ))
                self._safe_print("")
                continue

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
            self._safe_print("")

        self._validate_and_print_summary()
        return self.results

    def _validate_and_print_summary(self) -> None:
        """Validate results and print a final summary table of all actions taken."""
        if self.min_severity != Severity.LOW and not self.results:
            logger.warning(
                f"No alerts met the minimum severity threshold of {self.min_severity.value}. "
                "Analysis completed with no results to report."
            )
            self._safe_print(_SEPARATOR)
            self._safe_print("  SUMMARY")
            self._safe_print(_SEPARATOR)
            self._safe_print(f"  No alerts exceeded severity threshold {self.min_severity.value}.")
            self._safe_print(_SEPARATOR)
            self._safe_print("")
            return

        self._safe_print(_SEPARATOR)
        self._safe_print("  SUMMARY")
        self._safe_print(_SEPARATOR)
        self._safe_print(f"  {'Alert':<12} {'Severity':<10} {'IP':<18} {'Verdict':<12} {'Score':<8} {'Action'}")
        self._safe_print(f"  {'-'*10:<12} {'-'*8:<10} {'-'*16:<18} {'-'*10:<12} {'-'*6:<8} {'-'*10}")
        for r in self.results:
            self._safe_print(
                f"  {r.alert_id:<12} "
                f"{r.severity.value:<10} "
                f"{r.ip or 'N/A':<18} "
                f"{r.verdict.value if r.verdict else 'N/A':<12} "
                f"{str(r.score) if r.score is not None else '-':<8} "
                f"{r.action}"
            )
        self._safe_print(_SEPARATOR)
        self._safe_print("")
