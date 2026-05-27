# Suspicious Process Detector

A defensive Python tool that scans running processes and identifies potentially suspicious behavior based on simple detection rules.

This project is designed for educational and defensive security purposes. It does not kill processes, delete files, or perform destructive actions. It only collects process information, applies detection rules, calculates a risk score, and generates a JSON report.

---

## Overview

Suspicious Process Detector helps identify running processes that may require further investigation.

The tool checks for indicators such as:

- Processes running from suspicious directories
- Suspicious or commonly abused process names
- Lookalike process names
- Suspicious command-line keywords
- Missing executable paths
- High CPU or memory usage

The goal is not to replace an antivirus or EDR solution, but to demonstrate how defensive process analysis can be implemented in Python.

---

## Features

- Collects running process information
- Analyzes executable paths
- Detects suspicious directories
- Detects suspicious process names
- Detects suspicious command-line keywords
- Calculates a risk score
- Assigns severity levels: low, medium, high
- Generates a JSON report
- Modular and easy-to-maintain code structure
- Includes basic unit tests

---

## Ethical Use

This tool is intended only for educational, defensive, and authorized environments.

Use it only on:

- Your own computer
- Lab environments
- Systems where you have explicit permission

This project does not perform offensive actions and should not be used for unauthorized activity.

---

## Project Structure

```txt
suspicious-process-detector/
│
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
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
│           ├── directory_rules.py
│           ├── name_rules.py
│           └── command_rules.py
│
├── reports/
│   └── .gitkeep
│
├── logs/
│   └── .gitkeep
│
└── tests/
    ├── __init__.py
    ├── test_directory_rules.py
    ├── test_name_rules.py
    └── test_command_rules.py