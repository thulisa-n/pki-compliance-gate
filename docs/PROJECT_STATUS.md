# Project Status

This document tracks implemented capabilities in a detailed, phase-oriented format.

## Current Features (Phase 1 + Phase 2 + Phase 3 Complete)

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
  - `reports/sbom.cdx.json`
  - `reports/release_provenance.json`
  - `reports/release_provenance.json.sig`
  - `audit_evidence/policy_checks.json`
  - `audit_evidence/lint_results.json`
  - `audit_evidence/waiver_results.json`
  - `audit_evidence/opa_results.json`
  - `audit_evidence/evidence_manifest.json`
- **CI pipeline**
  - runs tests
  - executes compliance check
  - uploads artifacts
- **Phase 2 lint controls**
  - severity-aware zlint parsing
  - policy-driven fail severities (`lint.fail_severities`)
  - fallback behavior for non-JSON lint output

## Why This Split Exists

`README.md` stays concise for first-time readers, while this file preserves full implementation detail for reviewers, hiring managers, and audit-minded stakeholders.

## Upcoming Work

- **Phase 4 (enterprise alignment) - in progress**
  - APISEC expanded with TLS version policy checks, cipher posture checks, and chain posture signals
  - DCV attestation guardrails added (allowed methods + recency windows)
  - waiver-based false-positive controls added with audit traceability
  - optional OPA/Rego policy gate added for policy-as-code extension
  - SBOM generation and signed release provenance added to CI artifacts
  - deeper RFC 5280 extension profile checks added (SKI/AKI + critical extension linting)
  - RFC 5280 path linkage checks added (issuer-subject + AKI/SKI path links)
  - issuance attestation controls added (HSM-backed operations + FIPS level checks)
  - policy profile packs added for EV, S/MIME, Root Program, and CP/CPS overlays
- **Phase 5 (big-tech readiness) - not started**
