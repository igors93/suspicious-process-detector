"""
Shared data models used across the application.

Keeping models in a dedicated module makes the project easier to maintain,
test, and extend.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["low", "medium", "high"]
SignalStrength = Literal["weak", "strong"]


SEVERITY_RANK: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class ProcessInfo:
    """
    Represents relevant information about a running process.
    """

    pid: int
    name: str
    username: str | None
    executable_path: str | None
    command_line: str
    cpu_percent: float
    memory_percent: float
    ppid: int | None = None
    parent_name: str | None = None
    status: str | None = None
    created_at: str | None = None

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
        signal: Signal strength. Weak signals should not always alert alone.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    score: int
    signal: SignalStrength = "weak"

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