"""
Tests for process name detection rules.
"""

from suspicious_process_detector.models import ProcessInfo
from suspicious_process_detector.rules.name_rules import detect_suspicious_name


def test_detect_suspicious_process_name() -> None:
    process = ProcessInfo(
        pid=123,
        name="svchosts.exe",
        username="test",
        executable_path="/tmp/svchosts.exe",
        command_line="",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_name(process)

    assert len(findings) == 1
    assert findings[0].rule_id == "NAME_001"


def test_detect_lookalike_process_name() -> None:
    process = ProcessInfo(
        pid=123,
        name="scvhost.exe",
        username="test",
        executable_path="/tmp/scvhost.exe",
        command_line="",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_name(process)

    assert len(findings) == 1
    assert findings[0].rule_id == "NAME_002"