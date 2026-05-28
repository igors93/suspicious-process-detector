"""
Directory-based detection rules.

These rules look for processes running from locations commonly abused by
malware or suspicious scripts.
"""

from __future__ import annotations

from suspicious_process_detector.models import Finding, ProcessInfo

SUSPICIOUS_DIRECTORY_KEYWORDS: tuple[str, ...] = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/downloads",
    "/.cache",
    "/appdata/local/temp",
    "/windows/temp",
)


def detect_missing_executable_path(process: ProcessInfo) -> list[Finding]:
    """
    Detect processes where the executable path cannot be identified.

    This is a weak signal. Some legitimate system processes may not expose
    their executable path depending on permissions or operating system details.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if process.executable_path:
        return []

    return [
        Finding(
            rule_id="DIR_001",
            title="Missing executable path",
            description=(
                "The process executable path could not be identified. "
                "This may happen because of permissions, process type, "
                "or suspicious behavior."
            ),
            severity="low",
            score=1,
            signal="weak",
        )
    ]


def detect_suspicious_directory(process: ProcessInfo) -> list[Finding]:
    """
    Detect processes running from suspicious directories.

    Running executables from temporary folders, Downloads, or cache folders is
    not always malicious, but it is a strong indicator for manual review.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if not process.executable_path:
        return []

    normalized_path = _normalize_path(process.executable_path)
    findings: list[Finding] = []

    for directory_keyword in SUSPICIOUS_DIRECTORY_KEYWORDS:
        if directory_keyword in normalized_path:
            findings.append(
                Finding(
                    rule_id="DIR_002",
                    title="Process running from suspicious directory",
                    description=(
                        f"Process executable path contains suspicious "
                        f"directory keyword: {directory_keyword}"
                    ),
                    severity="medium",
                    score=4,
                    signal="strong",
                )
            )

    return findings


def _normalize_path(path: str) -> str:
    """
    Normalize paths for cross-platform comparison.

    Windows paths use backslashes, while Linux/macOS paths use forward slashes.
    This function converts backslashes to forward slashes and normalizes case.

    Args:
        path: Original file path.

    Returns:
        str: Lowercase normalized path.
    """
    return path.replace("\\", "/").casefold()