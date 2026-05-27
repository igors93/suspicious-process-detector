"""
Application entry point for Suspicious Process Detector.

This file should stay small. Its responsibility is to parse command-line
arguments and call the scanner workflow.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allows running the project with: python main.py
# without requiring package installation during the first version.
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


from suspicious_process_detector.scanner import ProcessScanner  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="suspicious-process-detector",
        description="Defensive tool to detect suspicious running processes.",
    )

    parser.add_argument(
        "--output",
        default="reports/process_report.json",
        help="Path where the JSON report will be saved.",
    )

    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity level to include in the final report.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of alerts to print in the terminal summary.",
    )

    return parser


def main() -> None:
    """
    Run the Suspicious Process Detector command-line application.
    """
    parser = build_parser()
    args = parser.parse_args()

    scanner = ProcessScanner()
    report_path, alerts = scanner.run(
        output_path=args.output,
        minimum_severity=args.min_severity,
    )

    print("\n[+] Suspicious Process Detector")
    print(f"[+] Report saved to: {report_path}")
    print(f"[+] Alerts found: {len(alerts)}")

    if not alerts:
        print("[+] No suspicious processes were detected.")
        return

    print("\nTop alerts:")
    for alert in alerts[: args.limit]:
        print(
            f"- [{alert.severity.upper()}] "
            f"PID={alert.process.pid} "
            f"NAME={alert.process.name} "
            f"SCORE={alert.risk_score}"
        )


if __name__ == "__main__":
    main()