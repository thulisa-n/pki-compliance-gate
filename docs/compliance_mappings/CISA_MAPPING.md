# CISA Compliance Mapping (Phase 3)

This document maps governance requirements to current and planned CertGuard controls.

## Mapping

### Requirement: Traceability of compliance decisions
- Implementation:
  - GitHub Actions run history
  - `reports/compliance_report.json`
  - `audit_evidence/policy_checks.json`
- Status: Implemented

### Requirement: Evidence integrity and tamper detection
- Implementation:
  - Planned signed hash manifest for evidence outputs
- Status: Planned (Phase 3)

### Requirement: Remediation and verification workflow
- Implementation:
  - `BugTriageAgent` for severity classification
  - `RemediationAgent` for actionable fix steps
  - `ComplianceAssuranceAgent` for post-fix governance verification
- Status: Implemented

### Requirement: Ongoing standards alignment
- Implementation:
  - `StandardsWatchAgent`
  - `policies/standards_baseline.yaml`
- Status: Implemented
