"""
Tests for command-line detection rules.
"""

from suspicious_process_detector.models import ProcessInfo
from suspicious_process_detector.rules.command_rules import detect_suspicious_commands


def test_detect_suspicious_command_keyword() -> None:
    process = ProcessInfo(
        pid=123,
        name="python",
        username="test",
        executable_path="/usr/bin/python",
        command_line="python script.py --payload base64",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_commands(process)

    assert len(findings) >= 1
    assert findings[0].rule_id == "CMD_001"


def test_no_suspicious_command_keyword() -> None:
    process = ProcessInfo(
        pid=123,
        name="python",
        username="test",
        executable_path="/usr/bin/python",
        command_line="python normal_script.py",
        cpu_percent=0.0,
        memory_percent=0.0,
    )

    findings = detect_suspicious_commands(process)

    assert findings == []