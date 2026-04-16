# CISA Compliance Mapping

This document maps governance requirements to CertGuard controls.

## Mapping

### Requirement: Traceability of compliance decisions
- Implementation:
  - GitHub Actions run history with downloadable artifact bundles
  - `reports/compliance_report.json` with per-check rule IDs and severity
  - `audit_evidence/policy_checks.json` with full CheckResult details
  - `audit_evidence/compliance_decisions.jsonl` with hash-chained decision log
  - `audit_evidence/evidence_manifest.json` indexing all evidence files per run
- Status: Implemented

### Requirement: Evidence integrity and tamper detection
- Implementation:
  - SHA-256 seal (`.seal`) generated for every compliance report
  - Ed25519-signed release provenance with in-CI verification
  - Append-only decision log with hash chaining (`previous_entry_hash` → `entry_hash`)
- Status: Implemented

### Requirement: Remediation and verification workflow
- Implementation:
  - `BugTriageAgent` for severity classification and next-action mapping
  - `RemediationAgent` for actionable fix steps with ownership assignment
  - `ComplianceAssuranceAgent` for post-fix governance verification
  - `--mode heal` for combined remediation + re-evaluation + assurance
- Status: Implemented

### Requirement: Ongoing standards alignment
- Implementation:
  - `StandardsWatchAgent` for policy drift detection against tracked baseline
  - `policies/standards_baseline.yaml` with auto-sync from CA/B Forum BR
  - `.github/workflows/standards-sync.yml` scheduled sync with automatic PR on drift
  - `ExternalSignalWatchAgent` for intake of external industry signals
- Status: Implemented

### Requirement: Supply-chain integrity
- Implementation:
  - CycloneDX SBOM generation in CI
  - Ed25519 artifact signing and verification
  - Kyverno `verifyImages` policy for container image signature verification
  - Signed provenance metadata (commit, workflow, artifact hashes)
- Status: Implemented
