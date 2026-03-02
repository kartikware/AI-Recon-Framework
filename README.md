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

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

Create a virtual environment:
python -m venv venv
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Ensure that Nmap is installed and accessible in your system PATH.
Usage
Run a scan against a target domain or IP address:

python main.py --target scanme.nmap.org

The tool will:
Execute an Nmap scan
Parse detected services and versions
Correlate findings with known CVEs via NVD
Escalate severity dynamically based on CVSS score
Generate AI-assisted contextual explanations
Save a structured Markdown report in the /reports directory
Risk Escalation Model
The framework recalibrates severity dynamically based on CVSS score:
CVSS ≥ 9.0 → CRITICAL
CVSS ≥ 7.0 → HIGH
CVSS ≥ 4.0 → MEDIUM
CVSS < 4.0 → LOW
This allows vulnerability intelligence to override static service-based risk classification, creating a more realistic prioritization model.
Design Philosophy
This project emphasizes:
Separation of concerns
Modular design
Clean data flow between components
Clear risk modeling abstraction
API-driven vulnerability intelligence
Explainable security analysis
The architecture enables future enhancements such as:
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
