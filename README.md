# CertGuard Engine

Automated PKI compliance gate for X.509 certificates using policy-as-code, pre-issuance validation, and CI/CD guardrails.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-pytest-informational)
![Policy](https://img.shields.io/badge/policy-CABF%20aligned-success)
![CI](https://img.shields.io/badge/ci-github%20actions-black)

---

## What This Does (in 10 seconds)

CertGuard Engine is a **policy-as-code PKI compliance gate** that:

- validates X.509 certificates against CAB Forum and RFC 5280-informed controls
- blocks non-compliant certificates in CI/CD pipelines
- generates audit-ready evidence and remediation plans
- simulates certificate authority pre-issuance compliance controls

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

## Why This Matters

A single non-compliant certificate can:

- break browser trust
- cause production outages
- introduce avoidable security risk

CertGuard helps prevent this by enforcing compliance before issuance, not after failure.

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

## Compliance Lifecycle (Core Concept)

CertGuard Engine models a governance workflow, not only a single pass/fail check:

`evaluate -> triage -> remediate/heal -> assure -> summary -> trend -> seal`

This reflects real compliance operations where violations are detected, classified, remediated, revalidated, tracked over time, and preserved as evidence.

---

## Example End-to-End Flow

1. Developer submits a certificate file or endpoint target.
2. CertGuard evaluates compliance checks.
3. Violations are detected (for example weak hash or missing SAN).
4. Triage classifies severity and next action.
5. Remediation guidance is generated.
6. Corrected certificate is revalidated.
7. Evidence is sealed for audit traceability.
8. Reviewer receives summary and trend outputs.

---

## Example Compliance Output

```text
Certificate: tests/certificates/valid_cert.pem
Compliant: YES
- [CAB-BR-6.3.2] validity_days: PASS (Certificate validity is 90 days (max 398))
- [RFC-5280-4.2.1.6] san_extension: PASS (SAN extension present)
- [CAB-BR-6.1.5] rsa_key_size: PASS (RSA key size is 2048 bits (min 2048))
- [CAB-BR-7.1.3] signature_algorithm: PASS (Signature algorithm is sha256)
- [CAB-BR-7.1.4.2.1] internal_domain_check: PASS (No blocked internal domains detected)
Lint: skipped
```

---

## Example APISEC Result

```text
Endpoint: https://api.example.com
TLS Version: TLSv1.2
Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Risk Level: MEDIUM
- endpoint_tls_version_policy: PASS
- endpoint_cipher_policy: PASS
- endpoint_signature_algorithm: PASS
- endpoint_chain_posture: FAIL (missing SKI/AKI linkage)
```

---

## Governance Agents

This project now includes governance-focused agents for operational readiness:

### Core Governance Agents

- **Bug Triage Agent**: classifies failed controls by severity and triage action
- **Remediation Agent**: generates targeted fix guidance for failed controls
- **Compliance Assurance Agent**: verifies control state after remediation

### Audit and Evidence Agents

- **Evidence Vault Agent**: seals reports with SHA-256 chain-of-custody metadata
- **Reviewer Summary Agent**: generates reviewer-ready markdown summaries
- **Trend Snapshot Agent**: writes run-level trend outputs for governance tracking

### Advanced Security Agents

- **Standards Watch Agent**: detects policy drift against tracked baselines
- **API TLS Posture Agent (APISEC)**: evaluates endpoint TLS posture for API-facing controls

These agents support an automation engineering workflow where controls, evidence, and remediation are all traceable.

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

### 5) Real-world endpoint posture demo

```bash
python src/main.py --mode apisec --endpoint https://example.com
```

This runs a live endpoint TLS posture check and returns a risk-oriented result for API-facing usage.

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

## Example Policy Mapping

| Rule ID | Description | Implementation |
| --- | --- | --- |
| `CAB-BR-6.3.2` | Max certificate validity window | `certificate.max_validity_days` -> `validity_days` check |
| `RFC-5280-4.2.1.6` | SAN extension required for identity matching | `certificate.require_san` -> `san_extension` check |
| `CAB-BR-6.1.5` | RSA key size must be 2048+ | `key.minimum_rsa_bits` -> `rsa_key_size` check |
| `CAB-BR-7.1.3` | Prohibited weak signature/hash algorithms | `signature.prohibited_algorithms` -> `signature_algorithm` check |
| `CAB-BR-7.1.4.2.1` | Internal names not allowed in public trust context | `domains.blocked_suffixes` -> `internal_domain_check` check |

---

## Industry Alignment

This project mirrors patterns commonly seen in:

- certificate authority pre-issuance validation pipelines
- certificate linting ecosystems (`zlint`, `pkilint`)
- DevSecOps compliance gates in CI/CD systems

It extends those patterns with governance agents, remediation workflows, and evidence sealing for audit traceability.

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

- **Phase 4 (enterprise alignment) - in progress**
  - expand APISEC checks (TLS version/cipher policies, cert chain posture) ✅
  - add SBOM generation and signed release provenance
  - deeper RFC 5280 coverage (extension profile and edge-case linting)
- **Phase 5 (big-tech readiness) - not started**
  - policy change approval workflows with stricter CODEOWNERS gating
  - observability metrics and trend dashboards for long-running governance
  - multi-environment compliance profiles (dev/staging/production)

Completed implementation history is documented in `docs/PROJECT_STATUS.md`.

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

Automation Engineer specializing in security automation, DevSecOps compliance gates, and PKI governance systems.

Currently building:

- CertGuard Engine: PKI compliance gate with policy-as-code, governance agents, and audit evidence
- QA automation frameworks and CI governance tooling

Focus areas:

Security automation | DevSecOps | PKI compliance engineering
