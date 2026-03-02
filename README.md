# AI-Assisted Reconnaissance & Vulnerability Prioritization Framework

## Overview

This project is a modular cybersecurity reconnaissance framework designed to automate vulnerability identification and risk prioritization.

It integrates:

- Nmap XML-based port scanning
- Structured service and version parsing
- Automated CVE correlation using the official NVD API
- Dynamic CVSS-based severity escalation
- AI-assisted vulnerability explanation layer
- Structured CLI output and Markdown reporting

The primary goal of this project is to explore automated risk modeling and vulnerability prioritization within offensive security workflows.

---

## Architecture
Target → Nmap Scan → XML Parser → Risk Engine → NVD CVE Lookup → CVSS Escalation → AI Explanation Layer → Report Generator
### Core Modules

- `scanner.py` — Executes Nmap and retrieves XML output
- `parser.py` — Extracts open ports, services, versions, and product metadata
- `risk_engine.py` — Applies baseline severity classification rules
- `cve_lookup.py` — Integrates with NVD API for vulnerability intelligence
- `ai_analyzer.py` — Provides contextual AI-based explanations
- `main.py` — CLI entry point and orchestration layer

---

## Key Features

- Modular and extensible architecture
- Real-time vulnerability intelligence via NVD
- Automated CVSS-based severity recalibration
- Service fingerprint normalization
- Exploit-aware risk modeling (extensible)
- Structured Markdown report generation
- Clean CLI interface for practical usage

---

Installation
1. Clone the Repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
2. Create and Activate a Virtual Environment
python -m venv venv

Linux / macOS:

source venv/bin/activate

Windows:

venv\Scripts\activate
3. Install Dependencies
pip install -r requirements.txt
4. Install Nmap

Ensure Nmap is installed and accessible in your system PATH.

Verify installation:

nmap --version

If not installed:

Linux:

sudo apt install nmap

macOS:

brew install nmap

Windows:
Download from: https://nmap.org/download.html

Usage

Run a scan against a target domain or IP address:

python main.py --target scanme.nmap.org
What the Tool Does

The framework will:

Execute an Nmap scan

Parse detected services and versions

Correlate findings with known CVEs via NVD

Escalate severity dynamically based on CVSS score

Generate AI-assisted contextual explanations

Save a structured Markdown report in the /reports directory

Risk Escalation Model

Severity is dynamically recalibrated based on CVSS score:

CVSS Score	Severity
≥ 9.0	CRITICAL
≥ 7.0	HIGH
≥ 4.0	MEDIUM
< 4.0	LOW

This allows vulnerability intelligence to override static service-based classifications, creating more realistic risk prioritization.

Design Philosophy

This project emphasizes:

Separation of concerns

Modular design

Clean data flow between components

Clear risk modeling abstraction

API-driven vulnerability intelligence

Explainable security analysis

Future Enhancements

The architecture supports:

CPE-based precision matching

Exploit availability correlation

Advanced attack surface modeling

AI-driven adaptive risk scoring

Multi-target scanning profiles

JSON output mode for automation workflows

Educational Purpose

This project is intended for educational purposes and authorized security testing only.

Users are responsible for ensuring compliance with applicable laws and regulations.

Author

Developed as part of a cybersecurity engineering and research-focused software development initiative.
