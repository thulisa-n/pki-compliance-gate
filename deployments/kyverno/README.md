# Kyverno Admission Controls

This directory contains Kubernetes admission policies that mirror CertGuard controls at cluster admission time.

## Policies Included

- `cert-validity-check.yaml`
  - validates cert-manager `Certificate` resources
  - enforces a 90-day maximum certificate duration (`2160h`)
  - defaults to `Audit` mode for safe rollout
- `default-cert-duration.yaml`
  - mutates `Certificate` resources to set a default duration when missing
  - demonstrates enablement-oriented policy automation
- `generate-namespace-networkpolicy.yaml`
  - generates a default-deny `NetworkPolicy` when new namespaces are created
  - demonstrates secure-by-default multi-tenant platform patterns

## Shift-Left Testing

- Test suite: `tests/kyverno-test.yaml`
- Fixtures: `tests/resources/*.yaml`

Run locally:

```bash
kyverno test deployments/kyverno/tests
```

## Rollout Pattern

1. Start with `validationFailureAction: Audit` to observe impact.
2. Review violations and tune issuer/team workflows.
3. Move to `validationFailureAction: Enforce` when ready.

## CI Integration

Workflow: `.github/workflows/kyverno-policy.yml`

- installs Kyverno CLI
- executes `kyverno test deployments/kyverno/tests`
- validates policy behavior on pull requests before merge

## Policy Reporting

See `docs/KYVERNO_POLICY_REPORTING.md` for commands and usage examples with:

- `ClusterPolicyReport`
- `PolicyReport`
- `kubectl` report inspection flow

## Why This Matters

CertGuard enforces policy in CI and evidence workflows. Kyverno adds runtime admission control so the same policy intent can be applied before Kubernetes resources are accepted.

In this repo, OPA/Rego policy evaluation is scoped to optional CI execution inside CertGuard, while Kyverno is the runtime admission example for Kubernetes clusters.
