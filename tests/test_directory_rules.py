"""
Tests for directory-based detection rules.
"""

from suspicious_process_detector.models import ProcessInfo
from suspicious_process_detector.rules.directory_rules import (
    detect_missing_executable_path,
    detect_suspicious_directory,
)


def test_detect_missing_executable_path() -> None:
    process = ProcessInfo(
        pid=123,
        name="unknown",
        username="test",
        executable_path=None,
        command_line="",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_missing_executable_path(process)

    assert len(findings) == 1
    assert findings[0].rule_id == "DIR_001"


def test_detect_suspicious_directory_downloads() -> None:
    process = ProcessInfo(
        pid=123,
        name="update.exe",
        username="test",
        executable_path="/home/user/Downloads/update.exe",
        command_line="",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_directory(process)

    assert len(findings) >= 1
    assert findings[0].rule_id == "DIR_002"

def test_detect_suspicious_directory_windows_temp() -> None:
    process = ProcessInfo(
        pid=123,
        name="update.exe",
        username="test",
        executable_path=r"C:\Users\Igor\AppData\Local\Temp\update.exe",
        command_line="",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_directory(process)

    assert len(findings) >= 1
    assert findings[0].rule_id == "DIR_002"