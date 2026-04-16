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

It is designed to demonstrate how compliance requirements translate into executable, testable, evidence-producing automation.

---

## Why This Matters

A single non-compliant certificate can break browser trust, cause production outages, or introduce avoidable security risk. In CA environments, pre-issuance compliance controls ensure certificates meet industry standards before they are trusted.

CertGuard enforces compliance before issuance, not after failure, using a shift-left model:

- **Policy-as-code:** rules are configurable, traceable, and version-controlled
- **Governance gate:** pipeline blocks violations with severity-based exit codes
- **Audit evidence:** JSON outputs support review, assurance, and audit workflows
- **Engineering discipline:** testable, repeatable, CI-driven validation

---

## Ethics and Attribution

This project uses public standards and public security research references for educational and portfolio purposes.

It is an independent implementation and is not affiliated with, endorsed by, or based on any non-public systems from external organizations.

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
- [CAB-BR-6.3.2] validity_days: PASS (Certificate validity is 90 days (max 200))
- [CAB-BR-7.1.4.2.1 / RFC-5280-4.2.1.6] san_extension: PASS (SAN extension present)
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

### 6) Optional DCV, waiver, and CI policy gate inputs

```bash
# Evaluate with DCV attestation and approved waivers
python src/main.py \
  --cert tests/certificates/valid_cert.pem \
  --dcv-attestation examples/dcv_attestation.json \
  --waiver-file examples/waivers.json

# Enable optional OPA/Rego CI gate via policy (policy.opa.enabled=true)
python src/main.py --cert tests/certificates/valid_cert.pem

# Include issuance controls attestation (HSM/FIPS)
python src/main.py \
  --cert tests/certificates/valid_cert.pem \
  --issuance-attestation examples/issuance_attestation.json

# Generate external signal snapshot + control recommendations
python src/main.py --mode signals --external-signals examples/external_signals.json
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
- `signals`: convert curated external signals into control recommendations

Severity-based exit codes (`evaluate` mode):

- `0` = fully compliant
- `1` = low severity failures
- `2` = medium/high severity failures, or lint-only failure
- `3` = critical failures

---

## Project Structure

```text
.github/workflows/      # CI compliance pipeline
policies/               # policy-as-code definitions
deployments/            # optional runtime enforcement examples
src/certguard/          # agents and orchestration engine
tests/                  # unit tests
reports/                # compliance report outputs
audit_evidence/         # policy, lint, and audit-decision evidence outputs
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
- `lint.enable_asn1parse`
- `lint.fail_on_asn1_error`
- `dcv.required`
- `dcv.allowed_methods`
- `dcv.max_age_days`
- `rfc5280.require_end_entity_not_ca`
- `rfc5280.require_key_usage`
- `rfc5280.required_key_usages`
- `rfc5280.require_subject_key_identifier`
- `rfc5280.require_authority_key_identifier`
- `rfc5280.allowed_critical_extensions`
- `rfc5280.require_path_issuer_subject_match`
- `rfc5280.require_path_aki_ski_match`
- `opa.enabled`
- `opa.policy_file`
- `issuance.require_hsm_attestation`
- `issuance.min_fips_level`
- `crypto_transition.enabled`
- `crypto_transition.target_max_validity_days`
- `crypto_transition.target_min_rsa_bits`
- `crypto_transition.approved_signature_algorithms`

Field-level policy notes are documented in `policies/README.md`.

Profile overlays for standards coverage breadth:

- `policies/profiles/ev_guidelines.yaml`
- `policies/profiles/smime_br.yaml`
- `policies/profiles/root_program_baseline.yaml`
- `policies/profiles/cpcps_controls.yaml`
- `policies/profiles/short_lived_90d.yaml`
- `policies/profiles/crypto_agility_pqc_readiness.yaml`

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
| `CAB-BR-7.1.4.2.1 / RFC-5280-4.2.1.6` | SAN required for public-trust profiles, with X.509 extension semantics from RFC 5280 | `certificate.require_san` -> `san_extension` check |
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

## Kubernetes Admission Control (Kyverno)

To demonstrate policy-to-enforcement capability beyond CI, CertGuard includes a Kyverno lifecycle set:

- `deployments/kyverno/cert-validity-check.yaml`
- `deployments/kyverno/default-cert-duration.yaml`
- `deployments/kyverno/generate-namespace-networkpolicy.yaml`
- `deployments/kyverno/verify-image-signatures.yaml`
- `deployments/kyverno/cleanup-failed-cert-requests.yaml`
- `deployments/kyverno/tests/kyverno-test.yaml`

These policies cover validation, mutation, generation, supply-chain verification, and lifecycle cleanup:

- validate cert-manager `Certificate` duration against `2160h` (90 days)
- mutate missing certificate durations to a secure default
- generate namespace-level default-deny network controls for secure-by-default onboarding
- verify signed container images at admission using Kyverno `verifyImages`
- clean up failed certificate requests marked for automated deletion

Kyverno CLI tests run in CI via `.github/workflows/kyverno-policy.yml` to enforce shift-left policy checks before merge.

Policy engine positioning in this project:

- `opa` section in `policies/cabf_policy.yaml`: optional CI/CD policy evaluation in CertGuard runs
- `deployments/kyverno/`: Kubernetes runtime admission enforcement example

Use this as a runtime complement to CertGuard's CI compliance gate.

Policy report visibility guidance:

- `docs/KYVERNO_POLICY_REPORTING.md`

### Example Kyverno Supply Chain Output

```text
policy: verify-signed-container-images
rule: require-signed-images
resource: Pod/signed-image-pod -> PASS
resource: Pod/unsigned-image-pod -> FAIL (signature verification failed)
```

---

## CI Pipeline

Workflow: `.github/workflows/compliance.yml`

Pipeline actions:

1. Install dependencies + zlint + OPA binaries
2. Execute `pytest` (64 tests)
3. Generate sample certificate
4. Run compliance gate (standard profile)
5. Run compliance gate with zlint + OPA enabled (`ci_lint_gate` profile)
6. Verify zlint and OPA executed (not skipped)
7. Generate reviewer summary + trend snapshot
8. Generate CycloneDX SBOM
9. Generate Ed25519-signed release provenance + in-CI verification
10. Upload compliance artifact bundle

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

- **Phase 1-4 (core engine through enterprise alignment): completed**
- **Phase 5 (crypto-agility and PQC readiness): completed**
- **Phase 6 (hardening): completed**

Detailed implementation history: `docs/PROJECT_STATUS.md`

---

## Scope and Limitations

This project implements **pre-issuance compliance controls** — the checks that happen before a certificate is issued or deployed.

### What is implemented

- Policy-as-code validation against CABF BR, EV Guidelines, S/MIME BR, Root Program, and CP/CPS control references
- 18+ compliance checks with CABF/RFC 5280 section-level traceability
- zlint integration (subprocess, severity-aware) — proven in CI via `ci_lint_gate` profile
- OPA/Rego policy gate — proven in CI with fail-closed behavior
- OpenSSL ASN.1 parsing integration
- RFC 5280 extension profile checks (SKI, AKI, key usage, basic constraints, critical extensions)
- RFC 5280 two-cert path linkage checks (issuer-subject DN match, AKI-SKI match)
- DCV attestation validation (method and recency checks against JSON evidence)
- Issuance attestation checks (HSM/FIPS level verification against policy thresholds)
- Ticketed, time-limited waiver system with audit traceability
- Append-only hash-chained compliance decision log
- Ed25519-signed release provenance with in-CI verification

### What is modeled but not fully implemented

- **Full RFC 5280 path validation**: current checks are two-cert linkage (issuer-subject, AKI-SKI), not recursive chain building with policy/name constraint processing
- **DCV execution**: DCV checks validate attestation evidence, not perform actual dns-01/http-01/tls-alpn-01 validation
- **HSM/PKCS#11 operations**: issuance checks validate attestation JSON, not interface with actual HSMs
- **cablint**: not integrated (zlint only)
- **CFSSL**: not integrated
- **Post-issuance lifecycle**: CRL distribution, OCSP stapling, CT log monitoring, and certificate renewal tracking are out of scope

### Design rationale

These boundaries are intentional. CertGuard focuses on the **policy validation and evidence generation** layer — the controls a compliance automation engineer builds and maintains. The hardware and protocol layers (HSM operations, DCV execution, CRL/OCSP serving) are operational infrastructure that this tool integrates with via attestation interfaces.

---

## Engineering Workflow

Changes follow a PR-first workflow with CI checks required before merge. Branch protection enforces review and status check gates on `main`.
