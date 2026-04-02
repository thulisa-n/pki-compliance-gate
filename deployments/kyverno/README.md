# Kyverno Admission Controls

This directory contains Kubernetes admission policies that mirror CertGuard controls at cluster admission time.

## Policy Included

- `cert-validity-check.yaml`
  - validates cert-manager `Certificate` resources
  - enforces a 90-day maximum certificate duration (`2160h`)
  - defaults to `Audit` mode for safe rollout

## Rollout Pattern

1. Start with `validationFailureAction: Audit` to observe impact.
2. Review violations and tune issuer/team workflows.
3. Move to `validationFailureAction: Enforce` when ready.

## Why This Matters

CertGuard enforces policy in CI and evidence workflows. Kyverno adds runtime admission control so the same policy intent can be applied before Kubernetes resources are accepted.
