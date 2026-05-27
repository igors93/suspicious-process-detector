"""
Harmless suspicious process simulator.

This script does not modify files, does not connect to the internet,
does not download anything, and does not execute system commands.

It only stays alive for a short time with suspicious-looking command-line
arguments so Suspicious Process Detector can detect it during a scan.
"""

from __future__ import annotations

import argparse
import time


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Harmless suspicious process simulator for testing."
    )

    parser.add_argument(
        "--encodedcommand",
        default="harmless-test-only",
        help="Fake suspicious-looking argument. It is not executed.",
    )

    parser.add_argument(
        "--payload",
        default="A" * 400,
        help="Long harmless string to simulate an unusually long command line.",
    )

    parser.add_argument(
        "--sleep",
        type=int,
        default=120,
        help="How many seconds the simulator should stay running.",
    )

    args = parser.parse_args()

    print("[+] Harmless suspicious process simulator is running.")
    print("[+] This script does not modify the system.")
    print("[+] It only stays alive so the detector can scan it.")
    print(f"[+] Sleeping for {args.sleep} seconds...")

    time.sleep(args.sleep)

    print("[+] Simulator finished.")


if __name__ == "__main__":
    main()