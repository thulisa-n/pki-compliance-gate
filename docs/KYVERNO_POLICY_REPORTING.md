# Kyverno Policy Reporting

This guide documents how to inspect Kubernetes policy compliance state after Kyverno policies are deployed.

## Why This Matters

Policy reports provide fleet-level visibility into which resources pass or fail policy checks. This supports audit readiness and operational follow-up workflows.

## Basic Report Commands

```bash
# Cluster-wide policy report summary
kubectl get clusterpolicyreports

# Namespace-scoped policy reports
kubectl get policyreports -A

# Inspect one report in detail
kubectl get clusterpolicyreport <report-name> -o yaml
```

## Example Report Signal

- policy: `enforce-90-day-max-validity`
- result: `fail`
- resource: `Certificate/too-long-cert`
- message: `Certificates must not exceed a 90-day validity period.`

Use this output to route remediation tasks and confirm that mutation/generation policies are reducing recurring violations over time.
