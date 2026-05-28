# Suspicious Process Detector

![Tests](https://github.com/igors93/suspicious-process-detector/actions/workflows/tests.yml/badge.svg)

A lightweight defensive Python tool that analyzes running processes, detects suspicious indicators, and generates alerts for manual investigation.

---

## What Is This Project?

Suspicious Process Detector is a rule-based defensive process analysis tool.

It scans processes currently running on the machine and looks for indicators that may suggest suspicious or potentially malicious behavior.

The goal is to help identify programs that are already running and may deserve manual investigation.

This project is designed for:

- defensive security learning
- Blue Team practice
- Python portfolio building
- process behavior analysis
- safe local experimentation

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
- scan inactive files on disk
- guarantee that a process is malicious

It only analyzes running processes and generates alerts.

After the user receives an alert, the investigation and response are manual.

---

## Current Features

- Scans running processes
- Collects process metadata
- Collects parent process information
- Detects suspicious directories
- Detects suspicious process names
- Detects lookalike process names
- Detects suspicious command-line keywords
- Detects possible command obfuscation
- Detects suspicious parent-child process relationships
- Detects known Windows system process names running from unexpected paths
- Uses weak and strong signal filtering
- Reduces noisy false positives from common applications
- Calculates a risk score
- Classifies alerts as low, medium, or high
- Generates a JSON report
- Includes a harmless suspicious process simulator for testing
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

The program only reads process information and writes a local JSON report.

---

## Detection Philosophy

The detector uses two types of signals:

```txt
weak   = weak indicator, usually not enough alone
strong = strong indicator, should generate an alert
```

Examples of weak signals:

```txt
long command line
high CPU usage
high memory usage
missing executable path
generic suspicious name
```

Examples of strong signals:

```txt
process running from Temp
process running from Downloads
lookalike process name
system process running from unexpected path
powershell with encodedcommand
command line using certutil or bitsadmin
browser spawning powershell or cmd
Office application spawning script interpreters
```

The analyzer only emits an alert when:

```txt
there is at least one strong signal
or multiple weak signals appear together
or the total risk score is high enough
```

This helps reduce false positives while still detecting suspicious running programs.

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
├── tools/
│   └── suspicious_process_simulator.py
│
├── reports/
│   └── .gitkeep
│
└── tests/
    ├── __init__.py
    ├── test_command_rules.py
    ├── test_directory_rules.py
    ├── test_name_rules.py
    ├── test_parent_rules.py
    └── test_risk_analyzer.py
```

---

## Requirements

- Python 3.10 or higher
- pip

Runtime dependency:

```txt
psutil
```

Development dependencies:

```txt
pytest
ruff
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

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Install runtime dependencies:

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
[+] Alerts found: 1

Top alerts:
- [MEDIUM] PID=3704 NAME=python3.10.exe SCORE=4
```

---

## Reports

By default, reports are saved to:

```txt
reports/process_report.json
```

The report contains:

- generated timestamp
- total alerts
- process metadata
- severity
- risk score
- detected findings
- finding descriptions
- signal type

Example finding:

```json
{
  "rule_id": "CMD_001",
  "title": "Possible command obfuscation",
  "description": "Command line contains possible obfuscation keyword: encodedcommand",
  "severity": "medium",
  "score": 4,
  "signal": "strong"
}
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

A process running from these directories is treated as a strong signal.

---

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

Generic names may be weak signals by themselves, but they can increase risk when combined with other indicators.

---

### Lookalike Process Names

Detects names that look similar to legitimate system processes.

Examples:

```txt
svhost.exe
scvhost.exe
expl0rer.exe
winlogin.exe
```

Lookalike process names are treated as stronger indicators because they may be trying to imitate legitimate processes.

---

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

These indicators are useful for identifying suspicious script execution, download behavior, or command obfuscation.

---

### Long Command Line Detection

Long command lines are common in browsers and Electron applications such as:

```txt
chrome.exe
msedge.exe
Code.exe
mscopilot.exe
Codex.exe
```

Because of this, the detector does not alert only because these applications have long command lines.

Long command line detection is currently focused on sensitive processes such as:

```txt
powershell.exe
cmd.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
regsvr32.exe
python.exe
python3.10.exe
bash
sh
```

---

### Parent-Child Process Indicators

Detects unusual parent-child process relationships.

Examples:

```txt
chrome.exe -> powershell.exe
msedge.exe -> cmd.exe
winword.exe -> powershell.exe
outlook.exe -> wscript.exe
excel.exe -> mshta.exe
```

These relationships are not always malicious, but they are useful signals for manual investigation.

---

### System Process Wrong Location

Detects known Windows system process names running from unexpected paths.

Examples:

```txt
svchost.exe running from Temp
lsass.exe running from Downloads
winlogon.exe running from AppData
services.exe running outside System32
```

This does not prove that the process is malicious, but it is a strong indicator for manual investigation.

---

## Risk Scoring

Each finding adds points to a process risk score.

Example scoring:

```txt
Missing executable path: +1
High CPU usage: +1
High memory usage: +1
Suspicious process name: +2
Unusually long command line: +1
Possible command obfuscation: +4
Command-line download activity: +4
Suspicious shell behavior: +4
Suspicious directory: +4
Lookalike process name: +4
Suspicious parent-child relationship: +4
System process running from unexpected path: +5
```

Severity:

```txt
0-3 points: low
4-7 points: medium
8+ points: high
```

---

## Testing With the Harmless Simulator

This repository includes a harmless simulator for testing detection rules.

The simulator is **not malware**.

It does not:

- modify files
- delete files
- download anything
- connect to the internet
- execute system commands
- change system settings

It only stays alive with suspicious-looking command-line arguments so the detector can identify it during a scan.

---

### Run the Simulator on Windows

Open a terminal in the project root and run:

```cmd
cd tools
python suspicious_process_simulator.py --encodedcommand fake-test --payload AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --sleep 300
```

Keep this terminal open.

Then open another terminal in the project root and run:

```cmd
python main.py --min-severity medium --limit 20
```

Expected result:

```txt
[MEDIUM] PID=... NAME=python.exe SCORE=4
```

or:

```txt
[MEDIUM] PID=... NAME=python3.10.exe SCORE=4
```

The alert should be triggered because the command line contains:

```txt
--encodedcommand
```

This activates the command obfuscation detection rule.

---

### Run the Simulator on Linux or macOS

Open a terminal in the project root and run:

```bash
cd tools
python3 suspicious_process_simulator.py --encodedcommand fake-test --payload AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --sleep 300
```

Keep this terminal open.

Then open another terminal in the project root and run:

```bash
python3 main.py --min-severity medium --limit 20
```

---

## Important Note About the Simulator

If you run only:

```bash
python tools/suspicious_process_simulator.py
```

the detector may not alert.

That happens because default Python arguments inside the script do not necessarily appear in the operating system process command line.

To trigger detection, pass suspicious-looking arguments directly in the command line:

```bash
--encodedcommand fake-test
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

Recommended development check:

```bash
python -m ruff check .
python -m pytest
python main.py
```

---

## Security Notice

Generated reports may contain sensitive local system information, such as:

- usernames
- process names
- executable paths
- command-line arguments

Do not upload real reports from your personal machine unless you review and sanitize them first.

Reports are ignored by Git through `.gitignore`.

---

## Ethical Use

Use this tool only on:

- your own computer
- lab environments
- systems where you have explicit permission

This project is defensive and educational.

---

## Limitations

This project only analyzes running processes.

It does not detect:

- inactive malware files on disk
- compressed files
- scripts that are not running
- persistence mechanisms that are not active
- registry modifications
- scheduled tasks unless their processes are running
- services that are installed but stopped

It also does not prove that a process is malicious. It only identifies suspicious indicators.

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
- Add process tree output
- Add optional local allowlist
- Add safer testing examples

---

## Contributing

Contributions are welcome.

Good first contributions include:

- adding new detection rules
- improving tests
- reducing false positives
- improving documentation
- adding Linux-specific rules
- adding Windows-specific rules
- improving report formats

Before submitting changes, run:

```bash
python -m ruff check .
python -m pytest
```

---

## License

This project is licensed under the MIT License.

---

## Disclaimer

This tool is provided for educational and defensive security purposes only.

It does not prove that a process is malicious. Alerts should always be reviewed manually.
