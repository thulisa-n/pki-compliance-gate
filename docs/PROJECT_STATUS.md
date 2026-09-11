# Project Status

This document tracks implemented capabilities in a detailed, phase-oriented format.

## Current Features (Phase 1 through Phase 6 Complete)

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
  - `reports/release_provenance.json.digest`
  - `reports/release_provenance.cosign.sig`
  - `reports/release_provenance.cosign.crt`
  - `reports/release_provenance.cosign.bundle`
  - `reports/release_provenance.identity.txt`
  - `audit_evidence/policy_checks.json`
  - `audit_evidence/lint_results.json`
  - `audit_evidence/waiver_results.json`
  - `audit_evidence/opa_results.json`
  - `audit_evidence/evidence_manifest.json`
  - `audit_evidence/compliance_decisions.jsonl`
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

## Completed Phases

- **Phase 4 (advanced controls) - completed**
  - APISEC expanded with TLS version policy checks, cipher posture checks, and chain posture signals
  - DCV attestation guardrails added (allowed methods + recency windows)
  - waiver-based false-positive controls added with audit traceability
  - optional OPA/Rego policy gate added for policy-as-code extension
  - SBOM generation and signed + verified release provenance artifacts added to CI outputs
  - deeper RFC 5280 extension profile checks added (SKI/AKI + critical extension linting)
  - RFC 5280 path linkage checks added (issuer-subject + AKI/SKI path links)
  - issuance attestation controls added (HSM-backed operations + FIPS level checks)
  - policy profile packs added for EV, S/MIME, Root Program, and CP/CPS overlays
- **Phase 5 (crypto-agility and PQC readiness) - completed**
  - crypto transition policy section added (`crypto_transition.*`) with defaults and schema validation
  - crypto transition checks added (validity target, RSA target, approved signature hash allowlist)
  - dedicated profile added: `policies/profiles/crypto_agility_pqc_readiness.yaml`
  - Kyverno lifecycle coverage added (validation, mutation, generation, CLI tests, policy reporting guidance)
  - Kyverno supply chain and lifecycle hygiene controls added (`verifyImages` and `ClusterCleanupPolicy`)
  - keyless cosign release provenance with OIDC identity and Rekor verification
  - append-only hash-chained compliance decision log
- **Phase 6 (hardening) - completed**
  - dedicated X509ParserAgent and fixture compliance tests
  - CABF BR term references populated across all policy profiles
  - zlint and OPA integrations proven in CI via `ci_lint_gate` profile
  - stale documentation and BR citation inconsistencies resolved
