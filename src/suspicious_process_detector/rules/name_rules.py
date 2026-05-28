"""
Process name detection rules.

These rules look for suspicious names, lookalike process names, and known
system process names running from unusual locations.
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

EXPECTED_WINDOWS_PROCESS_PATHS: dict[str, tuple[str, ...]] = {
    "svchost.exe": (
        "/windows/system32/svchost.exe",
        "/windows/syswow64/svchost.exe",
    ),
    "lsass.exe": (
        "/windows/system32/lsass.exe",
    ),
    "winlogon.exe": (
        "/windows/system32/winlogon.exe",
    ),
    "services.exe": (
        "/windows/system32/services.exe",
    ),
    "cmd.exe": (
        "/windows/system32/cmd.exe",
        "/windows/syswow64/cmd.exe",
    ),
    "powershell.exe": (
        "/windows/system32/windowspowershell/v1.0/powershell.exe",
        "/windows/syswow64/windowspowershell/v1.0/powershell.exe",
    ),
}


def detect_suspicious_name(process: ProcessInfo) -> list[Finding]:
    """
    Detect suspicious process names.

    Generic names are weak by themselves, while lookalike names are stronger
    indicators because they may be trying to imitate legitimate processes.

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
                severity="low",
                score=2,
                signal="weak",
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
                score=4,
                signal="strong",
            )
        )

    return findings


def detect_system_process_wrong_location(process: ProcessInfo) -> list[Finding]:
    """
    Detect known Windows system process names running from unexpected paths.

    This rule does not prove malicious behavior. It only identifies a process
    name and path combination that deserves manual review.

    Args:
        process: Process information.

    Returns:
        list[Finding]: Findings detected by this rule.
    """
    process_name = process.name.casefold().strip()

    if process_name not in EXPECTED_WINDOWS_PROCESS_PATHS:
        return []

    if not process.executable_path:
        return []

    normalized_path = _normalize_path(process.executable_path)
    expected_paths = EXPECTED_WINDOWS_PROCESS_PATHS[process_name]

    if normalized_path.endswith(expected_paths):
        return []

    return [
        Finding(
            rule_id="NAME_003",
            title="System process name running from unexpected path",
            description=(
                f"Process '{process.name}' is running from "
                f"'{process.executable_path}', which is not an expected "
                "location for this process name."
            ),
            severity="medium",
            score=5,
            signal="strong",
        )
    ]


def _normalize_path(path: str) -> str:
    """
    Normalize process paths for comparison.

    Args:
        path: Original process path.

    Returns:
        str: Normalized path.
    """
    return path.replace("\\", "/").casefold()