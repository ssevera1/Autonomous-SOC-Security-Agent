"""Core reasoning loop for the Autonomous Threat Hunter agent."""

import logging
import re

from .log_ingestor import LogIngestor
from .models import Alert, Verdict
from .remediation import request_remediation
from .tools import virustotal_ip_check

logger = logging.getLogger(__name__)

# Regex to extract IPv4 addresses from alert messages
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_SEPARATOR = "=" * 60


class ThreatHunterAgent:
    """Autonomous agent that ingests alerts, reasons about threats, and
    recommends remediation with human-in-the-loop approval."""

    def __init__(self, log_file: str) -> None:
        self.ingestor = LogIngestor(log_file)
        self.results: list[dict] = []

    # ----- reasoning steps -----

    def _step_extract_ip(self, alert: Alert) -> str | None:
        """Step 1: Extract the IP address from the alert message."""
        match = _IP_PATTERN.search(alert.message)
        if match:
            ip = match.group()
            print(f"  [EXTRACT]  Found IP: {ip}")
            return ip
        print("  [EXTRACT]  No IP address found — skipping alert.")
        return None

    def _step_check_reputation(self, ip: str) -> dict:
        """Step 2: Decide to check IP reputation via threat intelligence."""
        print(f"  [DECIDE]   Checking IP reputation via VirusTotal...")
        result = virustotal_ip_check(ip)
        print(f"  [ANALYZE]  Verdict: {result.verdict.value} (score: {result.score}/100)")
        print(f"             {result.details}")
        return result.model_dump()

    def _step_remediate(self, ip: str, verdict: str) -> str:
        """Step 3: If malicious, request human approval before blocking."""
        if verdict == Verdict.MALICIOUS.value:
            print(f"  [ACTION]   Threat confirmed — remediation required.")
            blocked = request_remediation(ip)
            return "BLOCKED" if blocked else "DECLINED"
        else:
            print(f"  [ACTION]   No threat detected — no action needed.")
            return "NO_ACTION"

    # ----- main loop -----

    def run(self) -> list[dict]:
        """Execute the full reasoning loop across all ingested alerts."""
        print()
        print(_SEPARATOR)
        print("  AUTONOMOUS THREAT HUNTER — Starting Analysis")
        print(_SEPARATOR)

        alerts = self.ingestor.ingest()
        print(f"\n  Loaded {len(alerts)} alerts. Beginning reasoning loop...\n")

        for alert in alerts:
            print(_SEPARATOR)
            print(f"  ALERT {alert.id}  |  {alert.severity.value}  |  {alert.source}")
            print(f"  {alert.message}")
            print("-" * 60)

            # Step 1 — Extract
            ip = self._step_extract_ip(alert)
            if ip is None:
                self.results.append({"alert_id": alert.id, "action": "SKIPPED"})
                print()
                continue

            # Step 2 — Analyze
            reputation = self._step_check_reputation(ip)

            # Step 3 — Act
            action = self._step_remediate(ip, reputation["verdict"])

            self.results.append({
                "alert_id": alert.id,
                "ip": ip,
                "verdict": reputation["verdict"],
                "score": reputation["score"],
                "action": action,
            })
            print()

        self._print_summary()
        return self.results

    def _print_summary(self) -> None:
        """Print a final summary table of all actions taken."""
        print(_SEPARATOR)
        print("  SUMMARY")
        print(_SEPARATOR)
        print(f"  {'Alert':<12} {'IP':<18} {'Verdict':<12} {'Score':<8} {'Action'}")
        print(f"  {'-'*10:<12} {'-'*16:<18} {'-'*10:<12} {'-'*6:<8} {'-'*10}")
        for r in self.results:
            print(
                f"  {r['alert_id']:<12} "
                f"{r.get('ip', 'N/A'):<18} "
                f"{r.get('verdict', 'N/A'):<12} "
                f"{str(r.get('score', '-')):<8} "
                f"{r['action']}"
            )
        print(_SEPARATOR)
        print()
