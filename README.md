# Suspicious Process Detector

![Tests](https://github.com/igors93/suspicious-process-detector/actions/workflows/tests.yml/badge.svg)

A lightweight defensive Python tool that scans running processes, detects suspicious indicators, and generates alerts for manual investigation.

---

## What Is This Project?

Suspicious Process Detector is a simple rule-based process analysis tool.

It scans currently running processes on a computer and looks for indicators that may deserve attention, such as suspicious process names, unusual execution paths, suspicious command-line keywords, and uncommon parent-child process relationships.

This project is designed for learning, defensive security practice, and portfolio building.

---

## What This Project Is Not

This project is **not an antivirus**.

It does not:

- remove malware
- delete files
- quarantine programs
- kill processes
- block threats
- modify system files
- guarantee that a process is malicious

It only analyzes running processes and generates alerts.

After the user receives an alert, the investigation and response are manual.

---

## Current Features

- Scans running processes
- Collects process metadata
- Detects suspicious directories
- Detects suspicious process names
- Detects lookalike process names
- Detects suspicious command-line keywords
- Detects possible obfuscated commands
- Detects suspicious parent-child process relationships
- Detects known system process names running from unusual paths
- Calculates a risk score
- Classifies alerts as low, medium, or high
- Generates a JSON report
- Runs tests with pytest
- Runs lint checks with Ruff
- Includes GitHub Actions CI

---

## How It Works

The tool follows this flow:

```txt
main.py
  ↓
ProcessScanner
  ↓
ProcessCollector
  ↓
RiskAnalyzer
  ↓
Detection Rules
  ↓
JsonReporter
  ↓
reports/process_report.json
```

The tool only reads process information and writes a local JSON report.

---

## Project Structure

```txt
suspicious-process-detector/
│
├── main.py
├── README.md
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── SECURITY.md
├── CONTRIBUTING.md
│
├── src/
│   └── suspicious_process_detector/
│       ├── __init__.py
│       ├── models.py
│       ├── scanner.py
│       ├── process_collector.py
│       ├── risk_analyzer.py
│       ├── reporter.py
│       │
│       └── rules/
│           ├── __init__.py
│           ├── command_rules.py
│           ├── directory_rules.py
│           ├── name_rules.py
│           └── parent_rules.py
│
├── reports/
│   └── .gitkeep
│
└── tests/
    ├── __init__.py
    ├── test_command_rules.py
    ├── test_directory_rules.py
    ├── test_name_rules.py
    └── test_parent_rules.py
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/igors93/suspicious-process-detector.git
cd suspicious-process-detector
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

For development:

```bash
pip install -r requirements-dev.txt
```

---

## Usage

Run the scanner:

```bash
python main.py
```

Save the report to a custom path:

```bash
python main.py --output reports/my_report.json
```

Show only medium and high alerts:

```bash
python main.py --min-severity medium
```

Limit terminal output:

```bash
python main.py --limit 5
```

---

## Example Output

```txt
[+] Suspicious Process Detector
[+] Report saved to: reports/process_report.json
[+] Alerts found: 2

Top alerts:
- [MEDIUM] PID=1234 NAME=update.exe SCORE=5
- [LOW] PID=4321 NAME=python.exe SCORE=1
```

---

## Detection Categories

### Directory Indicators

Detects processes running from locations commonly abused by suspicious scripts or unwanted programs.

Examples:

```txt
/tmp
/var/tmp
/dev/shm
/downloads
/.cache
/appdata/local/temp
/windows/temp
```

### Name Indicators

Detects suspicious or commonly abused process names.

Examples:

```txt
svchosts.exe
chrome_update.exe
system32.exe
winlogon32.exe
update.exe
service.exe
temp.exe
```

### Lookalike Process Names

Detects names that look similar to legitimate system processes.

Examples:

```txt
svhost.exe
scvhost.exe
expl0rer.exe
winlogin.exe
```

### Command-Line Indicators

Detects suspicious command-line patterns.

Examples:

```txt
encodedcommand
frombase64string
base64
invoke-webrequest
curl
wget
certutil
bitsadmin
chmod +x
/dev/tcp
netcat
```

### Parent-Child Process Indicators

Detects unusual parent-child process relationships.

Example:

```txt
chrome.exe -> powershell.exe
winword.exe -> cmd.exe
outlook.exe -> wscript.exe
```

These relationships are not always malicious, but they are useful signals for manual investigation.

---

## Risk Scoring

Each finding adds points to a process risk score.

Example:

```txt
Missing executable path: +1
Suspicious process name: +2
Suspicious command keyword: +2
Suspicious directory: +3
Lookalike process name: +3
Suspicious parent-child relationship: +3
System process running from unexpected path: +4
```

Severity:

```txt
0-3 points: low
4-7 points: medium
8+ points: high
```

---

## Running Tests

```bash
python -m pytest
```

---

## Running Lint

```bash
python -m ruff check .
```

Auto-fix simple lint issues:

```bash
python -m ruff check . --fix
```

---

## Security Notice

Generated reports may contain sensitive local system information, such as:

- usernames
- process names
- executable paths
- command-line arguments

Do not upload real reports from your personal machine unless you review and sanitize them first.

---

## Ethical Use

Use this tool only on:

- your own computer
- lab environments
- systems where you have explicit permission

This project is defensive and educational.

---

## Roadmap

Planned improvements:

- Add YAML-based custom rules
- Add watch mode for repeated scans
- Add trusted process baseline
- Add CSV report output
- Add HTML report output
- Add better Windows-specific rules
- Add better Linux-specific rules
- Add severity explanation in terminal output

---

## License

This project is licensed under the MIT License.

---

## Disclaimer

This tool is provided for educational and defensive security purposes only.

It does not prove that a process is malicious. Alerts should always be reviewed manually.