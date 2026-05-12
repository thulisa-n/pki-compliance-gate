# CertGuard Engine

CertGuard Engine validates X.509 certificates against policy rules and writes audit evidence that can be used in CI.

## What It Does

- Parses certificate metadata from PEM input.
- Evaluates checks from YAML policy files.
- Optionally runs `zlint`, `openssl asn1parse`, and OPA/Rego checks.
- Produces machine-readable reports, sealed evidence, and review artifacts.
- Exposes additional governance modes (`triage`, `assure`, `watch`, `heal`, `summary`, `trend`, `apisec`, `signals`).

## Requirements

- Python `3.11+`
- OpenSSL (for local cert generation and optional ASN.1 linting)
- Optional tooling for extended checks:
  - `zlint`
  - `opa`
  - Docker (only for docs artifact rendering workflow)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run Evaluate Mode

```bash
python src/main.py --cert tests/certificates/valid_cert.pem
```

JSON output:

```bash
python src/main.py --cert tests/certificates/valid_cert.pem --output json
```

Evaluate mode exit codes (`_exit_code_from_report` in `src/main.py`):

- `0`: compliant and no lint failure
- `1`: only low-severity policy failures
- `2`: medium/high policy failures or lint-only failure
- `3`: critical policy failure

## CLI Modes

- `evaluate`: run full compliance evaluation and evidence generation.
- `triage`: classify failed checks and suggest next action.
- `assure`: verify control state from a report.
- `watch`: detect drift between policy and standards baseline.
- `heal`: generate remediation actions and optionally re-check a healed cert.
- `summary`: write reviewer markdown summary from a report.
- `trend`: write run-level trend snapshot.
- `apisec`: evaluate endpoint TLS posture.
- `signals`: convert curated external signals into control recommendations.

Examples:

```bash
python src/main.py --mode triage --report-input reports/compliance_report.json
python src/main.py --mode watch --policy policies/cabf_policy.yaml --standards-baseline policies/standards_baseline.yaml
python src/main.py --mode apisec --endpoint https://example.com
python src/main.py --mode signals --external-signals examples/external_signals.json
```

## Inputs

- Policy file: `--policy` (default `policies/cabf_policy.yaml`)
- Certificate: `--cert` (required for `evaluate`)
- DCV attestation JSON: `--dcv-attestation`
- Issuance attestation JSON: `--issuance-attestation`
- Waiver JSON: `--waiver-file`
- Issuer cert (for path-linkage checks): `--issuer-cert`

## Outputs

Primary output paths:

- `reports/compliance_report.json`
- `reports/compliance_report.json.seal`
- `audit_evidence/policy_checks.json`
- `audit_evidence/lint_results.json`
- `audit_evidence/waiver_results.json`
- `audit_evidence/opa_results.json`
- `audit_evidence/evidence_manifest.json`
- `audit_evidence/compliance_decisions.jsonl`

Additional mode outputs:

- `reports/compliance_summary.md` (`summary`)
- `reports/compliance_trend_snapshot.json` (`trend`)
- `reports/standards_watch_report.json` (`watch`)
- `reports/external_signal_snapshot.json` and `reports/external_control_recommendations.json` (`signals`)

## Policy Files

- Base policy: `policies/cabf_policy.yaml`
- Profile overlays: `policies/profiles/`
- Standards baseline tracking: `policies/standards_baseline.yaml`
- Standards sync metadata: `policies/standards_sync_snapshot.yaml`
- Policy field reference: `policies/README.md`

## CI Workflows

- `compliance.yml`: tests, compliance run, fixture matrix, strict profile smoke, SBOM, provenance artifacts.
- `security-scans.yml`: Bandit and `pip-audit`.
- `codeql.yml`: GitHub CodeQL analysis.
- `standards-sync.yml`: scheduled CA/B Forum standards snapshot sync PRs.
- `standards-pr-guard.yml`: PR validation for standards snapshot YAML structure.
- `kyverno-policy.yml`: Kyverno policy tests.
- `docs-render.yml`: DOCX/PDF + redline artifact generation for docs changes.

Required check policy is configured in GitHub branch protection/rulesets (repository settings), not in this repository.

## Repository Layout

```text
src/certguard/           Core agents and engine
src/main.py              CLI entrypoint
policies/                Policy definitions and profiles
tests/                   Unit and integration-style tests
deployments/kyverno/     Kyverno policies and tests
scripts/                 Utility scripts
.github/workflows/       CI/CD workflows
```

## Documentation

- `docs/PROJECT_STATUS.md`
- `docs/COMPLIANCE_DEBUG_WALKTHROUGH.md`
- `docs/EVIDENCE_LIFECYCLE.md`
- `docs/KYVERNO_POLICY_REPORTING.md`
- `docs/compliance_mappings/CISA_MAPPING.md`

## Contributing

See `CONTRIBUTING.md`.
