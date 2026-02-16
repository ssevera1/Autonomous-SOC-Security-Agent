"""Remediation actions with mandatory human-in-the-loop approval."""

import logging

logger = logging.getLogger(__name__)


def block_ip(ip: str) -> None:
    """Execute the IP block action (simulated)."""
    print(f"  [EXECUTED] IP {ip} has been BLOCKED in the firewall.")
    logger.info("Blocked IP: %s", ip)


def request_remediation(ip: str) -> bool:
    """Request human approval before taking a destructive remediation action.

    Returns True if the IP was blocked, False if the analyst declined.
    """
    print()
    print(f"  ⚠  Requesting human approval to block IP {ip}...")
    print(f"     This action will add {ip} to the firewall deny list.")
    print()

    while True:
        try:
            response = input("  >> Do you approve blocking this IP? (Y/N): ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\n  [SKIPPED] No input received — defaulting to deny.")
            logger.info("No input for IP %s — auto-denied", ip)
            return False
        if response == "Y":
            block_ip(ip)
            return True
        elif response == "N":
            print(f"  [SKIPPED] Analyst declined to block IP {ip}.")
            logger.info("Analyst declined to block IP: %s", ip)
            return False
        else:
            print("     Please enter Y or N.")
