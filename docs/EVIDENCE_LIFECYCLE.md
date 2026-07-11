# Evidence Lifecycle

This document defines how compliance evidence is generated, named, retained, and reviewed.

## Artifact Naming

CI bundles evidence under a run-specific path:

### Compliance report and governance outputs

- `artifacts/<github_run_id>/compliance_report.json`
- `artifacts/<github_run_id>/compliance_report.json.seal`
- `artifacts/<github_run_id>/compliance_summary.md`
- `artifacts/<github_run_id>/compliance_trend_snapshot.json`

### Audit evidence

- `artifacts/<github_run_id>/policy_checks.json`
- `artifacts/<github_run_id>/lint_results.json`
- `artifacts/<github_run_id>/waiver_results.json`
- `artifacts/<github_run_id>/opa_results.json`
- `artifacts/<github_run_id>/evidence_manifest.json`
- `artifacts/<github_run_id>/compliance_decisions.jsonl`

### Supply chain and provenance

- `artifacts/<github_run_id>/sbom.cdx.json`
- `artifacts/<github_run_id>/release_provenance.json`
- `artifacts/<github_run_id>/release_provenance.json.digest`
- `artifacts/<github_run_id>/release_provenance.cosign.sig`
- `artifacts/<github_run_id>/release_provenance.cosign.crt`
- `artifacts/<github_run_id>/release_provenance.cosign.bundle`

This provides deterministic traceability from evidence to workflow execution context.

### Trust model scope

- Runs using cosign keyless artifacts (`release_provenance.cosign.*`) are verified with GitHub OIDC identity + Rekor proof.
- Older runs that only contain `release_signing_public_key.b64` / `release_provenance.json.sig` used the legacy co-located key model and are outside the keyless trust scope.

## Retention Guidance

- Keep evidence artifacts for at least one sprint cycle for engineering review.
- For audit-focused checkpoints, export and archive run bundles externally.
- Preserve release-associated evidence snapshots (`v*` tags) as immutable records.

## Review Workflow

1. Verify `compliance_report.json` and compliance status.
2. Verify integrity seal (`compliance_report.json.seal`).
3. Verify control detail outputs (`policy_checks.json`, `lint_results.json`, `opa_results.json`).
4. Verify waiver application (`waiver_results.json`).
5. Review decision log integrity (`compliance_decisions.jsonl` hash chain).
6. Review trend signal (`compliance_trend_snapshot.json`).
7. Verify release provenance signature with cosign keyless identity validation:
   - `cosign verify-blob --bundle release_provenance.cosign.bundle --certificate release_provenance.cosign.crt --signature release_provenance.cosign.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github.com/thulisa-n/pki-compliance-gate/.github/workflows/compliance.yml@refs/heads/main$' release_provenance.json`
   - For PR workflow evidence, use `^https://github.com/thulisa-n/pki-compliance-gate/.github/workflows/compliance.yml@refs/pull/[0-9]+/merge$`.
8. Record reviewer note in PR or issue using `compliance_summary.md`.
