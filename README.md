# CertGuard Engine

Automated PKI compliance gate for X.509 certificates using policy-as-code, pre-issuance validation, and CI/CD guardrails.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-pytest-informational)
![Policy](https://img.shields.io/badge/policy-CABF%20aligned-success)
![CI](https://img.shields.io/badge/ci-github%20actions-black)

---

## Overview

`CertGuard Engine` is a compliance-focused security automation project designed to mirror how modern CA pipelines enforce pre-issuance controls.

The engine converts standards into executable checks:

1. Parse certificate metadata
2. Validate against policy-as-code rules
3. Run optional linting controls
4. Generate machine-readable audit evidence

This repo is intentionally built as a portfolio-quality project for PKI compliance and security automation roles.

---

## Why This Project

For certificate ecosystems, one non-compliant issuance can create significant operational and trust risk.  
This project demonstrates a shift-left compliance model:

- **Policy-as-code:** rules are configurable and traceable
- **Governance gate:** pipeline blocks violations
- **Audit evidence:** JSON outputs support review and assurance workflows
- **Engineering discipline:** testable, repeatable, CI-driven validation

---

## Architecture

```text
Certificate Input
      |
      v
X.509 Parser Agent
      |
      v
Policy Validator Agent
      |
      v
Compliance Gate Engine
      |
   +--+---------------------+
   |                        |
   v                        v
Compliance Report      Audit Evidence
```

---

## Current Features (Phase 1)

- **X.509 parsing agent**
  - subject, issuer, validity window, SAN, signature hash, key details
- **Policy validation agent**
  - max validity days
  - required SAN extension
  - minimum RSA key size
  - prohibited hash algorithms
  - internal domain suffix blocking
- **Compliance gate engine**
  - pass/fail decision with explicit check results
- **Evidence generation**
  - `reports/compliance_report.json`
  - `audit_evidence/policy_checks.json`
  - `audit_evidence/lint_results.json`
- **CI pipeline**
  - runs tests
  - executes compliance check
  - uploads artifacts

---

## Quick Start

### 1) Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2) Generate a sample certificate

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 90 -nodes \
  -keyout /tmp/certguard.key \
  -out /tmp/certguard.pem \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
```

### 3) Run compliance gate

```bash
python src/main.py --cert /tmp/certguard.pem
```

Exit code behavior:

- `0` = compliant
- `1` = non-compliant

---

## Project Structure

```text
.github/workflows/      # CI compliance pipeline
policies/               # policy-as-code definitions
src/certguard/          # agents and orchestration engine
tests/                  # unit tests
reports/                # compliance report outputs
audit_evidence/         # policy and lint evidence outputs
```

---

## CI Pipeline

Workflow: `.github/workflows/compliance.yml`

Pipeline actions:

1. Install dependencies
2. Execute `pytest`
3. Generate sample certificate
4. Run compliance gate
5. Upload compliance artifacts

This creates visible governance evidence directly in GitHub Actions.

---

## Roadmap

- **Phase 2**
  - zlint enablement with structured severity handling
  - expanded certificate fixtures for regression checks
- **Phase 3**
  - CISA-style chain-of-custody metadata
  - CISSP-aligned identity and access controls for gated actions
- **Phase 4**
  - API/TLS endpoint posture checks for API security workflows

---

## Engineering Workflow

This project is managed using a Jira-like GitHub Projects flow:

`Backlog -> Ready -> In Progress -> Review -> Done`

Each feature is tracked with issue-to-PR traceability to reflect real-world security engineering processes.

---

## Career Positioning

This repository is part of a two-repo portfolio strategy:

- **QA/AI orchestration repo:** demonstrates automation architecture and test governance
- **CertGuard Engine:** demonstrates PKI compliance automation, policy-as-code, and CI guardrails

Together, they support a transition path:

`QA Automation Engineer -> Security Automation Engineer -> PKI Compliance Engineer`
