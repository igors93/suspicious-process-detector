"""
Shared data models used across the application.

Keeping models in a dedicated module makes the project easier to maintain,
test, and extend.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


Severity = Literal["low", "medium", "high"]


SEVERITY_RANK: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class ProcessInfo:
    """
    Represents relevant information about a running process.

    Attributes:
        pid: Process ID.
        name: Process name.
        username: User that owns the process.
        executable_path: Full path to the process executable, when available.
        command_line: Command line used to start the process.
        cpu_percent: CPU usage percentage.
        memory_percent: Memory usage percentage.
    """

    pid: int
    name: str
    username: str | None
    executable_path: str | None
    command_line: str
    cpu_percent: float
    memory_percent: float

    def to_dict(self) -> dict:
        """
        Convert process information to a dictionary.

        Returns:
            dict: Dictionary representation of the process.
        """
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """
    Represents a single suspicious finding detected by a rule.

    Attributes:
        rule_id: Unique identifier for the rule.
        title: Short finding title.
        description: Detailed explanation of the finding.
        severity: Finding severity.
        score: Numeric risk score added by this finding.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    score: int

    def to_dict(self) -> dict:
        """
        Convert finding to a dictionary.

        Returns:
            dict: Dictionary representation of the finding.
        """
        return asdict(self)


@dataclass(frozen=True)
class ProcessAlert:
    """
    Represents a suspicious process alert.

    Attributes:
        process: Process information.
        findings: List of findings detected for the process.
        risk_score: Total risk score.
        severity: Final alert severity.
        detected_at: UTC timestamp when the alert was generated.
    """

    process: ProcessInfo
    findings: list[Finding]
    risk_score: int
    severity: Severity
    detected_at: str

    def to_dict(self) -> dict:
        """
        Convert alert to a dictionary suitable for JSON reports.

        Returns:
            dict: Dictionary representation of the alert.
        """
        return {
            "detected_at": self.detected_at,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "process": self.process.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def calculate_severity(score: int) -> Severity:
    """
    Calculate final severity based on the total risk score.

    Args:
        score: Total risk score.

    Returns:
        Severity: low, medium, or high.
    """
    if score >= 8:
        return "high"

    if score >= 4:
        return "medium"

    return "low"


def is_severity_allowed(current: Severity, minimum: Severity) -> bool:
    """
    Check if a severity level should be included based on a minimum severity.

    Args:
        current: Current alert severity.
        minimum: Minimum severity required.

    Returns:
        bool: True if current severity is equal or higher than minimum.
    """
    return SEVERITY_RANK[current] >= SEVERITY_RANK[minimum]