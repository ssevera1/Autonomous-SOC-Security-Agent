"""Remediation actions with mandatory human-in-the-loop approval."""

import logging
import signal

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 30  # seconds


def _timeout_handler(signum, frame):
    """Handle timeout during input request."""
    raise TimeoutError("Input request timed out")


def block_ip(ip: str) -> None:
    """Execute the IP block action (simulated)."""
    print(f"  [EXECUTED] IP {ip} has been BLOCKED in the firewall.")
    logger.info("Blocked IP: %s", ip)


def request_remediation(ip: str) -> bool:
    """Request human approval before taking a destructive remediation action.

    Returns True if the IP was blocked, False if the analyst declined.
    """
    print()
    print(f"  [!!] Requesting human approval to block IP {ip}...")
    print(f"     This action will add {ip} to the firewall deny list.")
    print()

    _MAX_ATTEMPTS = 3
    for attempt in range(_MAX_ATTEMPTS):
        try:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(_REQUEST_TIMEOUT)
            try:
                response = input("  >> Do you approve blocking this IP? (Y/N): ").strip().upper()
            finally:
                signal.alarm(0)
        except TimeoutError:
            print(f"\n  [SKIPPED] Request timed out -- defaulting to deny.")
            logger.warning("Remediation request timeout for IP %s", ip)
            return False
        except (EOFError, KeyboardInterrupt):
            print("\n  [SKIPPED] No input received -- defaulting to deny.")
            logger.info("No input for IP %s -- auto-denied", ip)
            return False
        except Exception as e:
            print(f"\n  [SKIPPED] Error during approval request -- defaulting to deny.")
            logger.error("Error requesting remediation approval for IP %s: %s", ip, e)
            return False
        if response == "Y":
            block_ip(ip)
            return True
        elif response == "N":
            print(f"  [SKIPPED] Analyst declined to block IP {ip}.")
            logger.info("Analyst declined to block IP: %s", ip)
            return False
        else:
            remaining = _MAX_ATTEMPTS - attempt - 1
            if remaining:
                print(f"     Please enter Y or N. ({remaining} attempt(s) remaining)")
            else:
                print("  [SKIPPED] Too many invalid responses -- defaulting to deny.")
                logger.info("Too many invalid responses for IP %s -- auto-denied", ip)
    return False
