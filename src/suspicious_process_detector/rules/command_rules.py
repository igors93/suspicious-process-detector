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

SENSITIVE_LONG_COMMAND_PROCESSES: tuple[str, ...] = (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bash",
    "sh",
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
    findings.extend(_detect_long_command_line(process.name, process.command_line))

    return findings


def _detect_obfuscation_keywords(command_line: str) -> list[Finding]:
    """
    Detect possible command obfuscation indicators.

    Args:
        command_line: Normalized command line.

    Returns:
        list[Finding]: Findings detected by this rule.
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
                    score=4,
                    signal="strong",
                )
            ]

    return []


def _detect_download_keywords(command_line: str) -> list[Finding]:
    """
    Detect command-line download indicators.

    Args:
        command_line: Normalized command line.

    Returns:
        list[Finding]: Findings detected by this rule.
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
                    score=4,
                    signal="strong",
                )
            ]

    return []


def _detect_shell_behavior_keywords(command_line: str) -> list[Finding]:
    """
    Detect suspicious shell behavior indicators.

    Args:
        command_line: Normalized command line.

    Returns:
        list[Finding]: Findings detected by this rule.
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
                    score=4,
                    signal="strong",
                )
            ]

    return []


def _detect_long_command_line(process_name: str, command_line: str) -> list[Finding]:
    """
    Detect unusually long command lines for sensitive processes only.

    Long command lines are common in browsers and Electron apps. For this
    reason, this rule only applies to shells, scripting engines, and similar
    sensitive processes.

    Args:
        process_name: Process name.
        command_line: Original command line.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if len(command_line) < MAX_COMMAND_LINE_LENGTH:
        return []

    if not _is_sensitive_long_command_process(process_name):
        return []

    return [
        Finding(
            rule_id="CMD_004",
            title="Unusually long command line",
            description=(
                "Sensitive process has an unusually long command line. "
                "This can be legitimate, but may indicate obfuscation or "
                "scripted execution."
            ),
            severity="low",
            score=1,
            signal="weak",
        )
    ]


def _is_sensitive_long_command_process(process_name: str) -> bool:
    """
    Check if a process should be evaluated for long command lines.

    Python executables can have versioned names such as python3.10.exe,
    so they are detected by prefix.

    Args:
        process_name: Process name.

    Returns:
        bool: True if this process should be checked for long command lines.
    """
    normalized_name = process_name.casefold().strip()

    is_sensitive_process = normalized_name in SENSITIVE_LONG_COMMAND_PROCESSES
    is_python_process = normalized_name.startswith("python")

    return is_sensitive_process or is_python_process