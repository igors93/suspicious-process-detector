"""
Tests for parent-child process relationship rules.
"""

from suspicious_process_detector.models import ProcessInfo
from suspicious_process_detector.rules.parent_rules import (
    detect_suspicious_parent_child,
)


def test_detect_suspicious_parent_child_relationship() -> None:
    process = ProcessInfo(
        pid=123,
        name="powershell.exe",
        username="test",
        executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe",
        cpu_percent=0.0,
        memory_percent=0.0,
        ppid=100,
        parent_name="chrome.exe",
    )

    findings = detect_suspicious_parent_child(process)

    assert len(findings) == 1
    assert findings[0].rule_id == "PARENT_001"


def test_no_parent_child_finding_for_normal_relationship() -> None:
    process = ProcessInfo(
        pid=123,
        name="chrome.exe",
        username="test",
        executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        command_line="chrome.exe",
        cpu_percent=0.0,
        memory_percent=0.0,
        ppid=100,
        parent_name="explorer.exe",
    )

    findings = detect_suspicious_parent_child(process)

    assert findings == []