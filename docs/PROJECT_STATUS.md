# Project Status

This document tracks implemented capabilities in a detailed, phase-oriented format.

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

## Why This Split Exists

`README.md` stays concise for first-time readers, while this file preserves full implementation detail for reviewers, hiring managers, and audit-minded stakeholders.
