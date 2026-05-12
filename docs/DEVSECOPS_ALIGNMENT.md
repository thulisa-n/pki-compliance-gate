# DevSecOps Alignment

This document maps CertGuard capabilities to practical DevSecOps outcomes and defines the next maturity steps.

## Current Alignment

| DevSecOps principle | Current implementation |
| --- | --- |
| Shift security left | Security checks run on `pull_request` via GitHub Actions workflows |
| Security as code | Policy and controls are codified in `policies/*.yaml` and optional Rego (`policies/rego/`) |
| Continuous validation | Automated checks in `compliance.yml`, `security-scans.yml`, `codeql.yml`, `secrets-scan.yml`, `iac-scan.yml` |
| Risk-based decisions | Severity-based evaluate exit codes (`0/1/2/3`) in `src/main.py` |
| Controlled exceptions | Waiver workflow with required ticket and expiry in `src/certguard/engine.py` |
| API security checks | API TLS posture mode (`--mode apisec`) in `src/certguard/agents/api_tls_posture.py` |

## Security Gate Model

- **Block immediately**: critical vulnerabilities or high/medium policy failures.
- **Track with urgency**: low-severity failures.
- **Allow with controls**: only approved, time-bound waivers (ticket + expiry).

This keeps delivery velocity while avoiding silent risk acceptance.

## Feedback Loop Targets

Use these targets to keep security feedback fast and actionable:

- **MTTD (pipeline)**: detect issues on PR checks (same commit cycle).
- **Critical remediation SLA**: within 24 hours.
- **High remediation SLA**: within 3 business days.
- **Medium remediation SLA**: within 7 business days.
- **Low remediation SLA**: next planned hardening cycle.

## Recommended Metrics to Track

- count of failed security checks per PR
- waiver count and waiver expiry breaches
- mean remediation time by severity
- repeated failure patterns by rule/check
- weekly trend from `trend` mode snapshots

## Scope Note

Container image scanning is intentionally not included yet because this repository does not currently ship container images.

## Next 30-Day Maturity Plan

1. Publish weekly security-gate trend summaries from existing artifacts.
2. Add severity-to-SLA labels in triage/summary outputs.
3. Alert on waivers nearing expiry.
4. Add CI-safe APISEC smoke checks against controlled test endpoints.
