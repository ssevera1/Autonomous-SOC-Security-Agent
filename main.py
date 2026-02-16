#!/usr/bin/env python3
"""Entry point for the Autonomous Threat Hunter agent."""

import logging
import sys
from pathlib import Path

from threat_hunter.agent import ThreatHunterAgent


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        handlers=[logging.FileHandler("threat_hunter.log")],
    )

    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_alerts.json"
    if not Path(log_file).exists():
        print(f"Error: log file '{log_file}' not found.")
        sys.exit(1)

    agent = ThreatHunterAgent(log_file)
    agent.run()


if __name__ == "__main__":
    main()
