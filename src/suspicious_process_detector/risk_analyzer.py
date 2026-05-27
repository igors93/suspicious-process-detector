"""
Risk analysis module.

This module receives process information and applies detection rules.
It does not collect process data and does not save reports.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from suspicious_process_detector.models import (
    Finding,
    ProcessAlert,
    ProcessInfo,
    calculate_severity,
)
from suspicious_process_detector.rules.command_rules import detect_suspicious_commands
from suspicious_process_detector.rules.directory_rules import (
    detect_missing_executable_path,
    detect_suspicious_directory,
)
from suspicious_process_detector.rules.name_rules import detect_suspicious_name

RuleFunction = Callable[[ProcessInfo], list[Finding]]


class RiskAnalyzer:
    """
    Applies rules to processes and generates alerts.

    New rules can be added by creating a function that receives ProcessInfo
    and returns a list of Finding objects.
    """

    def __init__(
        self,
        rules: list[RuleFunction] | None = None,
        high_cpu_threshold: float = 80.0,
        high_memory_threshold: float = 20.0,
    ) -> None:
        """
        Initialize the risk analyzer.

        Args:
            rules: Optional custom list of rule functions.
            high_cpu_threshold: CPU percentage considered suspicious.
            high_memory_threshold: Memory percentage considered suspicious.
        """
        self.rules = rules or [
            detect_missing_executable_path,
            detect_suspicious_directory,
            detect_suspicious_name,
            detect_suspicious_commands,
            self._detect_high_resource_usage,
        ]

        self.high_cpu_threshold = high_cpu_threshold
        self.high_memory_threshold = high_memory_threshold

    def analyze(self, process: ProcessInfo) -> ProcessAlert | None:
        """
        Analyze a single process.

        Args:
            process: Process information to analyze.

        Returns:
            ProcessAlert | None: Alert if suspicious findings exist.
        """
        findings: list[Finding] = []

        for rule in self.rules:
            findings.extend(rule(process))

        if not findings:
            return None

        risk_score = sum(finding.score for finding in findings)
        severity = calculate_severity(risk_score)

        return ProcessAlert(
            process=process,
            findings=findings,
            risk_score=risk_score,
            severity=severity,
            detected_at=self._utc_now(),
        )

    def analyze_many(self, processes: list[ProcessInfo]) -> list[ProcessAlert]:
        """
        Analyze many processes and return alerts sorted by risk score.

        Args:
            processes: List of process information objects.

        Returns:
            list[ProcessAlert]: Sorted alerts, highest risk first.
        """
        alerts: list[ProcessAlert] = []

        for process in processes:
            alert = self.analyze(process)

            if alert is not None:
                alerts.append(alert)

        return sorted(alerts, key=lambda item: item.risk_score, reverse=True)

    def _detect_high_resource_usage(self, process: ProcessInfo) -> list[Finding]:
        """
        Detect high CPU or memory usage.

        High resource usage alone does not mean malware. This rule produces
        low severity findings because it should be treated as a weak signal.
        """
        findings: list[Finding] = []

        if process.cpu_percent >= self.high_cpu_threshold:
            findings.append(
                Finding(
                    rule_id="RESOURCE_001",
                    title="High CPU usage",
                    description=(
                        f"Process is using {process.cpu_percent}% CPU, "
                        f"which is above the configured threshold of "
                        f"{self.high_cpu_threshold}%."
                    ),
                    severity="low",
                    score=1,
                )
            )

        if process.memory_percent >= self.high_memory_threshold:
            findings.append(
                Finding(
                    rule_id="RESOURCE_002",
                    title="High memory usage",
                    description=(
                        f"Process is using {process.memory_percent}% memory, "
                        f"which is above the configured threshold of "
                        f"{self.high_memory_threshold}%."
                    ),
                    severity="low",
                    score=1,
                )
            )

        return findings

    @staticmethod
    def _utc_now() -> str:
        """
        Return current UTC time in ISO 8601 format.

        Returns:
            str: UTC timestamp.
        """
        return datetime.now(timezone.utc).isoformat()