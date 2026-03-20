# Evidence Lifecycle

This document defines how compliance evidence is generated, named, retained, and reviewed.

## Artifact Naming

CI bundles evidence under a run-specific path:

- `artifacts/<github_run_id>/compliance_report.json`
- `artifacts/<github_run_id>/compliance_report.json.seal`
- `artifacts/<github_run_id>/compliance_summary.md`
- `artifacts/<github_run_id>/compliance_trend_snapshot.json`
- `artifacts/<github_run_id>/policy_checks.json`
- `artifacts/<github_run_id>/lint_results.json`
- `artifacts/<github_run_id>/evidence_manifest.json`

This provides deterministic traceability from evidence to workflow execution context.

## Retention Guidance

- Keep evidence artifacts for at least one sprint cycle for engineering review.
- For audit-focused checkpoints, export and archive run bundles externally.
- Preserve release-associated evidence snapshots (`v*` tags) as immutable records.

## Review Workflow

1. Verify `compliance_report.json` and status.
2. Verify integrity seal (`compliance_report.json.seal`).
3. Verify control detail outputs (`policy_checks.json`, `lint_results.json`).
4. Review trend signal (`compliance_trend_snapshot.json`).
5. Record reviewer note in PR or issue using `compliance_summary.md`.
