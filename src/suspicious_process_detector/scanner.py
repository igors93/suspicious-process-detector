"""
Scanner workflow module.

This module coordinates the process collection, risk analysis, filtering,
and report generation steps.
"""

from __future__ import annotations

from pathlib import Path

from suspicious_process_detector.models import (
    ProcessAlert,
    Severity,
    is_severity_allowed,
)
from suspicious_process_detector.process_collector import ProcessCollector
from suspicious_process_detector.reporter import JsonReporter
from suspicious_process_detector.risk_analyzer import RiskAnalyzer


class ProcessScanner:
    """
    High-level scanner that runs the full detection workflow.
    """

    def __init__(
        self,
        collector: ProcessCollector | None = None,
        analyzer: RiskAnalyzer | None = None,
        reporter: JsonReporter | None = None,
    ) -> None:
        """
        Initialize the scanner.

        Dependency injection keeps the code easier to test and extend.
        """
        self.collector = collector or ProcessCollector()
        self.analyzer = analyzer or RiskAnalyzer()
        self.reporter = reporter or JsonReporter()

    def run(
        self,
        output_path: str | Path,
        minimum_severity: Severity = "low",
    ) -> tuple[Path, list[ProcessAlert]]:
        """
        Run the complete scan workflow.

        Args:
            output_path: Path where the JSON report will be saved.
            minimum_severity: Minimum severity to include in the report.

        Returns:
            tuple[Path, list[ProcessAlert]]: Report path and generated alerts.
        """
        processes = self.collector.collect()
        alerts = self.analyzer.analyze_many(processes)

        filtered_alerts = [
            alert
            for alert in alerts
            if is_severity_allowed(alert.severity, minimum_severity)
        ]

        saved_report_path = self.reporter.save(
            alerts=filtered_alerts,
            output_path=output_path,
        )

        return saved_report_path, filtered_alerts