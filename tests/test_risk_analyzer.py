"""
Tests for risk analyzer alert filtering.
"""

from suspicious_process_detector.models import Finding, ProcessInfo
from suspicious_process_detector.risk_analyzer import RiskAnalyzer


def test_analyzer_does_not_alert_on_single_weak_signal() -> None:
    process = ProcessInfo(
        pid=123,
        name="chrome.exe",
        username="test",
        executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        command_line="chrome.exe",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    analyzer = RiskAnalyzer(
        rules=[
            lambda _: [
                Finding(
                    rule_id="TEST_001",
                    title="Weak test finding",
                    description="Weak signal used for testing.",
                    severity="low",
                    score=1,
                    signal="weak",
                )
            ]
        ]
    )

    alert = analyzer.analyze(process)

    assert alert is None


def test_analyzer_alerts_on_strong_signal() -> None:
    process = ProcessInfo(
        pid=123,
        name="powershell.exe",
        username="test",
        executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -encodedcommand test",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    analyzer = RiskAnalyzer(
        rules=[
            lambda _: [
                Finding(
                    rule_id="TEST_002",
                    title="Strong test finding",
                    description="Strong signal used for testing.",
                    severity="medium",
                    score=4,
                    signal="strong",
                )
            ]
        ]
    )

    alert = analyzer.analyze(process)

    assert alert is not None
    assert alert.risk_score == 4
    assert alert.severity == "medium"