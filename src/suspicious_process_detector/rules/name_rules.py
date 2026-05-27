"""
Process name detection rules.

These rules look for suspicious or commonly abused process names.
"""

from __future__ import annotations

from suspicious_process_detector.models import Finding, ProcessInfo

SUSPICIOUS_PROCESS_NAMES: tuple[str, ...] = (
    "svchosts.exe",
    "chrome_update.exe",
    "system32.exe",
    "winlogon32.exe",
    "update.exe",
    "service.exe",
    "temp.exe",
)


LOOKALIKE_PROCESS_NAMES: tuple[str, ...] = (
    "svhost.exe",
    "scvhost.exe",
    "expl0rer.exe",
    "winlogin.exe",
)


def detect_suspicious_name(process: ProcessInfo) -> list[Finding]:
    """
    Detect suspicious process names.

    This does not mean the process is malicious. It only means the name
    deserves investigation.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    process_name = process.name.casefold().strip()
    findings: list[Finding] = []

    if process_name in SUSPICIOUS_PROCESS_NAMES:
        findings.append(
            Finding(
                rule_id="NAME_001",
                title="Suspicious process name",
                description=(
                    f"Process name '{process.name}' is commonly abused "
                    "or too generic."
                ),
                severity="medium",
                score=2,
            )
        )

    if process_name in LOOKALIKE_PROCESS_NAMES:
        findings.append(
            Finding(
                rule_id="NAME_002",
                title="Lookalike process name",
                description=(
                    f"Process name '{process.name}' looks similar to a "
                    "legitimate system process."
                ),
                severity="medium",
                score=3,
            )
        )

    return findings