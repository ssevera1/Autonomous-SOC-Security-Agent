"""Shared guard for arming a SIGALRM-based timeout safely."""

import signal
import threading


def alarm_supported() -> bool:
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
