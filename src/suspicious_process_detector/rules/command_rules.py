"""
Command-line detection rules.

These rules inspect process command lines for suspicious keywords often seen
in malicious scripts, droppers, or living-off-the-land activity.
"""

from __future__ import annotations

from suspicious_process_detector.models import Finding, ProcessInfo

SUSPICIOUS_COMMAND_KEYWORDS: tuple[str, ...] = (
    "encodedcommand",
    "invoke-webrequest",
    "iex",
    "frombase64string",
    "base64",
    "curl ",
    "wget ",
    "chmod +x",
    "/dev/tcp",
    "netcat",
    " nc ",
    "certutil",
    "bitsadmin",
)


def detect_suspicious_commands(process: ProcessInfo) -> list[Finding]:
    """
    Detect suspicious command-line keywords.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if not process.command_line:
        return []

    normalized_command = process.command_line.casefold()
    findings: list[Finding] = []

    for keyword in SUSPICIOUS_COMMAND_KEYWORDS:
        if keyword in normalized_command:
            findings.append(
                Finding(
                    rule_id="CMD_001",
                    title="Suspicious command-line keyword",
                    description=(
                        f"Command line contains suspicious keyword: {keyword}"
                    ),
                    severity="medium",
                    score=2,
                )
            )

    return findings