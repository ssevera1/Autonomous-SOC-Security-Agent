#!/usr/bin/env python3
"""Entry point for the Autonomous Threat Hunter agent."""

import argparse
import logging
import sys
from pathlib import Path

from threat_hunter.agent import ThreatHunterAgent
from threat_hunter.models import Severity


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous Threat Hunter - SOC Security Agent")
    parser.add_argument("log_file", nargs="?", default="sample_alerts.json", help="Path to SIEM alert JSON file")
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        metavar="LEVEL",
        help="Skip alerts below this severity. Choices: LOW (default, process all), MEDIUM, HIGH, CRITICAL",
    )
    parser.add_argument("--verbose", action="store_true", help="Also print structured log output to console")
    args = parser.parse_args()

    handlers: list[logging.Handler] = [logging.FileHandler("threat_hunter.log")]
    if args.verbose:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        handlers=handlers,
    )

    if not Path(args.log_file).exists():
        print(f"Error: log file '{args.log_file}' not found.")
        sys.exit(1)

    agent = ThreatHunterAgent(args.log_file, min_severity=Severity(args.min_severity))
    agent.run()


if __name__ == "__main__":
    main()
