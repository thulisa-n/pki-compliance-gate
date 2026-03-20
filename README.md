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

## Security Context

In certificate authority environments, pre-issuance compliance controls help ensure certificates meet industry standards before they are trusted by browsers and operating systems.

CertGuard Engine simulates this style of control pipeline by converting policy requirements into automated validation checks, governance decisions, and audit evidence outputs.

---

## System Architecture

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

## Example Compliance Output

```text
Certificate: tests/certificates/valid_cert.pem
Compliant: YES
- validity_days: PASS (Certificate validity is 90 days (max 398))
- san_extension: PASS (SAN extension present)
- rsa_key_size: PASS (RSA key size is 2048 bits (min 2048))
- signature_algorithm: PASS (Signature algorithm is sha256)
- internal_domain_check: PASS (No blocked internal domains detected)
Lint: skipped
```

---

## Governance Agents

This project now includes governance-focused agents for operational readiness:

- **Bug Triage Agent**
  - classifies failed controls by severity
  - suggests remediation actions for each failed check
- **Compliance Assurance Agent**
  - confirms required controls are present and passing after fixes
  - validates final compliance state against governance expectations
- **Standards Watch Agent**
  - compares current policy to tracked standards baseline
  - reports policy drift and recommends updates
- **Remediation Agent**
  - produces actionable fix steps for failed controls
  - supports heal-and-recheck workflow with assurance verification
- **Evidence Vault Agent**
  - seals generated compliance reports using SHA-256 fingerprints
  - records execution metadata for chain-of-custody and audit integrity
- **Reviewer Summary Agent**
  - generates markdown summaries for reviewers and PR discussions
- **Trend Snapshot Agent**
  - creates run-level trend snapshots for governance visibility
- **API TLS Posture Agent (APISEC)**
  - evaluates endpoint certificate posture for API-facing security checks

These agents support an automation engineering workflow where controls, evidence, and remediation are all traceable.

---

## Current Features (Phase 1 + Phase 2 Complete, Phase 3 Started)

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
  - compliance score and risk classification output
  - severity-based exit codes for pipeline-friendly behavior
- **Evidence generation**
  - `reports/compliance_report.json`
  - `reports/compliance_report.json.seal`
  - `reports/compliance_summary.md`
  - `reports/compliance_trend_snapshot.json`
  - `audit_evidence/policy_checks.json`
  - `audit_evidence/lint_results.json`
  - `audit_evidence/evidence_manifest.json`
- **CI pipeline**
  - runs tests
  - executes compliance check
  - uploads artifacts
- **Phase 2 lint controls**
  - severity-aware zlint parsing
  - policy-driven fail severities (`lint.fail_severities`)
  - fallback behavior for non-JSON lint output

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

### 4) Run governance agents

```bash
# Bug triage from latest compliance report
python src/main.py --mode triage --report-input reports/compliance_report.json

# Assurance confirmation from latest compliance report
python src/main.py --mode assure --report-input reports/compliance_report.json

# Standards drift watch against baseline
python src/main.py --mode watch \
  --policy policies/cabf_policy.yaml \
  --standards-baseline policies/standards_baseline.yaml \
  --watch-output reports/standards_watch_report.json

# Remediation plan + healed recheck
python src/main.py --mode heal \
  --report-input reports/compliance_report.json \
  --healed-cert tests/certificates/valid_cert.pem \
  --healed-report reports/healed_compliance_report.json

# Reviewer-friendly markdown summary
python src/main.py --mode summary \
  --report-input reports/compliance_report.json \
  --summary-output reports/compliance_summary.md

# Trend snapshot for governance tracking
python src/main.py --mode trend \
  --report-input reports/compliance_report.json \
  --trend-output reports/compliance_trend_snapshot.json

# APISEC endpoint TLS posture check
python src/main.py --mode apisec --endpoint https://api.example.com

# Explainability output with standards context
python src/main.py --cert tests/certificates/sha1_cert.pem --explain

# Machine-readable output mode
python src/main.py --cert tests/certificates/valid_cert.pem --output json
```

Mode summary:

- `evaluate`: run core compliance checks and generate evidence
- `triage`: classify failed controls by severity and remediation priority
- `assure`: verify required controls still satisfy governance expectations
- `watch`: detect policy drift against tracked standards baseline
- `heal`: generate remediation plan and re-check healed certificate state
- `summary`: generate reviewer-friendly markdown compliance summary
- `trend`: generate compliance trend snapshot JSON
- `apisec`: evaluate endpoint TLS posture for API security review

Severity-based exit codes (`evaluate` mode):

- `0` = fully compliant
- `1` = low severity failures
- `2` = medium/high severity failures
- `3` = critical failures

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

## Policy-as-Code Fields

Core policy file: `policies/cabf_policy.yaml`

- `certificate.max_validity_days`
- `certificate.require_san`
- `key.minimum_rsa_bits`
- `signature.prohibited_algorithms`
- `domains.forbid_internal_names`
- `domains.blocked_suffixes`
- `lint.enable_zlint`
- `lint.fail_on_error`
- `lint.fail_severities`

Field-level policy notes are documented in `policies/README.md`.

---

## Standards References

This project implements simplified controls informed by:

- CA/Browser Forum Baseline Requirements
- RFC 5280 (X.509 certificate and CRL profile)

The standards baseline tracker is maintained in `policies/standards_baseline.yaml`.

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

Trigger modes:

- push to `main`
- pull request validation
- scheduled regression run (twice weekly)
- manual run (`workflow_dispatch`)

Protected workflow control:

- Manual dispatch supports optional `protected_run`
- Protected mode enforces GitHub Actions + protected ref context checks

Fixture matrix validation:

- CI validates multiple fixture scenarios with expected exit-code assertions
- ensures control behavior remains stable across valid and failure cases

---

## Roadmap

- **Phase 3 (completed)**
  - chain-of-custody report sealing and evidence manifests
  - role-aware protected run controls
  - reviewer summary, trend snapshots, fixture matrix CI checks
  - API TLS posture mode for initial APISEC coverage
- **Phase 4 (enterprise alignment)**
  - expand APISEC checks (TLS version/cipher policies, cert chain posture)
  - add SBOM generation and signed release provenance
  - deeper RFC 5280 coverage (extension profile and edge-case linting)
- **Phase 5 (big-tech readiness)**
  - policy change approval workflows with stricter CODEOWNERS gating
  - observability metrics and trend dashboards for long-running governance
  - multi-environment compliance profiles (dev/staging/production)

---

## Learning Path (Educational Build)

This repo is designed to be educational for automation engineers moving into security compliance.

1. **Understand the certificate parser output**
   - run `python src/main.py --cert tests/certificates/valid_cert.pem`
   - inspect `reports/compliance_report.json`
2. **Trace policy-to-check mapping**
   - change one value in `policies/cabf_policy.yaml`
   - rerun and observe which checks change
3. **Practice red/green validation**
   - run against `tests/certificates/sha1_cert.pem` and `tests/certificates/internal_domain_cert.pem`
   - compare compliant vs non-compliant outputs
4. **Read audit evidence**
   - inspect `audit_evidence/policy_checks.json`
   - inspect `audit_evidence/lint_results.json`
5. **Use CI as governance evidence**
   - review workflow artifacts in GitHub Actions for each run

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

---

## About the Author

Automation Engineer transitioning into Security and PKI Compliance Engineering.

Currently building:

- CertGuard Engine: PKI compliance gate with policy-as-code, governance agents, and audit evidence
- QA automation frameworks and CI governance tooling

Focus areas:

Security automation | DevSecOps | PKI compliance engineering
