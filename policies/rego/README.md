# Generated Rego

This directory is **not** a source of truth. The validity limit lives in the
YAML profile (`certificate.max_validity_days`).

Emit a gate that matches the loaded policy:

```bash
pki-gate --mode export-rego \
  --policy policies/cabf_policy.yaml \
  --summary-output policies/rego/validity.rego
```

When `opa.enabled` is true, the engine generates the same Rego at evaluation
time and does not read a checked-in `.rego` file for the limit.
