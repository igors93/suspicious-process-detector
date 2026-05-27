"""
Command-line detection rules.

These rules inspect process command lines for suspicious keywords often seen
in scripts, droppers, or living-off-the-land activity.
"""

from __future__ import annotations

from suspicious_process_detector.models import Finding, ProcessInfo


MAX_COMMAND_LINE_LENGTH = 300

OBFUSCATION_KEYWORDS: tuple[str, ...] = (
    "encodedcommand",
    "frombase64string",
    "base64",
)

DOWNLOAD_KEYWORDS: tuple[str, ...] = (
    "invoke-webrequest",
    "curl ",
    "wget ",
    "certutil",
    "bitsadmin",
)

SHELL_BEHAVIOR_KEYWORDS: tuple[str, ...] = (
    "iex",
    "chmod +x",
    "/dev/tcp",
    "netcat",
    " nc ",
)


def detect_suspicious_commands(process: ProcessInfo) -> list[Finding]:
    """
    Detect suspicious command-line indicators.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if not process.command_line:
        return []

    normalized_command = process.command_line.casefold()
    findings: list[Finding] = []

    findings.extend(_detect_obfuscation_keywords(normalized_command))
    findings.extend(_detect_download_keywords(normalized_command))
    findings.extend(_detect_shell_behavior_keywords(normalized_command))
    findings.extend(_detect_long_command_line(process.command_line))

    return findings


def _detect_obfuscation_keywords(command_line: str) -> list[Finding]:
    """
    Detect possible command obfuscation indicators.
    """
    for keyword in OBFUSCATION_KEYWORDS:
        if keyword in command_line:
            return [
                Finding(
                    rule_id="CMD_001",
                    title="Possible command obfuscation",
                    description=(
                        f"Command line contains possible obfuscation "
                        f"keyword: {keyword}"
                    ),
                    severity="medium",
                    score=3,
                )
            ]

    return []


def _detect_download_keywords(command_line: str) -> list[Finding]:
    """
    Detect command-line download indicators.
    """
    for keyword in DOWNLOAD_KEYWORDS:
        if keyword in command_line:
            return [
                Finding(
                    rule_id="CMD_002",
                    title="Possible command-line download activity",
                    description=(
                        f"Command line contains download-related "
                        f"keyword: {keyword}"
                    ),
                    severity="medium",
                    score=2,
                )
            ]

    return []


def _detect_shell_behavior_keywords(command_line: str) -> list[Finding]:
    """
    Detect suspicious shell behavior indicators.
    """
    for keyword in SHELL_BEHAVIOR_KEYWORDS:
        if keyword in command_line:
            return [
                Finding(
                    rule_id="CMD_003",
                    title="Suspicious shell behavior",
                    description=(
                        f"Command line contains shell behavior "
                        f"keyword: {keyword}"
                    ),
                    severity="medium",
                    score=2,
                )
            ]

    return []


def _detect_long_command_line(command_line: str) -> list[Finding]:
    """
    Detect unusually long command lines.

    Long command lines are not always suspicious, but they may indicate
    obfuscation or scripted execution.
    """
    if len(command_line) < MAX_COMMAND_LINE_LENGTH:
        return []

    return [
        Finding(
            rule_id="CMD_004",
            title="Unusually long command line",
            description=(
                "Process command line is unusually long. This can be "
                "legitimate, but may deserve manual review."
            ),
            severity="low",
            score=1,
        )
    ]