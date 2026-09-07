"""Remediation actions with mandatory human-in-the-loop approval."""

import logging
import signal
import sys
import threading

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 120  # seconds -- generous enough to read a CRITICAL alert before deciding


def _timeout_handler(signum, frame):
    """Handle timeout during input request."""
    raise TimeoutError("Input request timed out")


def _alarm_supported() -> bool:
    """Whether we can safely arm a SIGALRM-based timeout in this process.

    `signal.signal()` raises `ValueError` off the main thread and `SIGALRM` /
    `setitimer` don't exist on Windows, so callers must check this before
    arming rather than relying on a broad `except` to paper over it.
    """
    return (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )


def _flush_pending_stdin() -> None:
    """Discard any input buffered during a timed-out prompt.

    Without this, a keystroke the analyst makes just after the timeout fires
    (intended as the answer to *this* alert) sits in the tty buffer and gets
    consumed by the next alert's `input()` call instead.
    """
    if not sys.stdin.isatty():
        return
    try:
        import termios
    except ImportError:
        return
    try:
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except termios.error:
        pass


def block_ip(ip: str) -> None:
    """Execute the IP block action (simulated)."""
    print(f"  [EXECUTED] IP {ip} has been BLOCKED in the firewall.")
    logger.info("Blocked IP: %s", ip)


def request_remediation(ip: str, timeout: float = _REQUEST_TIMEOUT) -> bool:
    """Request human approval before taking a destructive remediation action.

    Args:
        ip: The IP address to block.
        timeout: Seconds to wait for an analyst response before auto-denying.

    Returns True if the IP was blocked, False if the analyst declined.
    """
    print()
    print(f"  [!!] Requesting human approval to block IP {ip}...")
    print(f"     This action will add {ip} to the firewall deny list.")
    print()

    use_alarm = _alarm_supported()

    _MAX_ATTEMPTS = 3
    for attempt in range(_MAX_ATTEMPTS):
        previous_handler = None
        previous_timer = None
        if use_alarm:
            previous_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            response = input("  >> Do you approve blocking this IP? (Y/N): ").strip().upper()
        except TimeoutError:
            print("\n  [SKIPPED] Request timed out -- defaulting to deny.")
            logger.warning("Remediation request timeout for IP %s", ip)
            _flush_pending_stdin()
            return False
        except (EOFError, KeyboardInterrupt):
            print("\n  [SKIPPED] No input received -- defaulting to deny.")
            logger.info("No input for IP %s -- auto-denied", ip)
            return False
        except (OSError, ValueError) as e:
            print("\n  [SKIPPED] Error during approval request -- defaulting to deny.")
            logger.error("Error requesting remediation approval for IP %s: %s", ip, e)
            return False
        finally:
            if use_alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
                if previous_timer and previous_timer[0] > 0:
                    signal.setitimer(signal.ITIMER_REAL, *previous_timer)
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
