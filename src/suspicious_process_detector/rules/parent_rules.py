"""
Parent-child process relationship rules.

These rules look for unusual process relationships that may deserve manual
investigation. They do not prove malicious behavior.
"""

from __future__ import annotations

from suspicious_process_detector.models import Finding, ProcessInfo

SUSPICIOUS_PARENT_PROCESSES: tuple[str, ...] = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "outlook.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "acrord32.exe",
    "thunderbird.exe",
)

SUSPICIOUS_CHILD_PROCESSES: tuple[str, ...] = (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "python.exe",
    "pythonw.exe",
    "bash",
    "sh",
)


def detect_suspicious_parent_child(process: ProcessInfo) -> list[Finding]:
    """
    Detect unusual parent-child process relationships.

    Example:
        chrome.exe spawning powershell.exe may deserve investigation.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    if not process.parent_name:
        return []

    parent_name = process.parent_name.casefold().strip()
    child_name = process.name.casefold().strip()

    if _is_suspicious_relationship(parent_name, child_name):
        return [
            Finding(
                rule_id="PARENT_001",
                title="Suspicious parent-child process relationship",
                description=(
                    f"Parent process '{process.parent_name}' started "
                    f"child process '{process.name}'. This relationship "
                    "may deserve manual investigation."
                ),
                severity="medium",
                score=4,
                signal="strong",
            )
        ]

    return []


def _is_suspicious_relationship(parent_name: str, child_name: str) -> bool:
    """
    Check if a parent-child relationship should be considered suspicious.
    """
    return (
        parent_name in SUSPICIOUS_PARENT_PROCESSES
        and child_name in SUSPICIOUS_CHILD_PROCESSES
    )