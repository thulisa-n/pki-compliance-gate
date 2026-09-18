# Security Policy

## Supported versions

The latest published `pki-compliance-gate` release on PyPI and the matching
GitHub tag are supported. Older tags are snapshots; please reproduce against
current `main` or the latest tag before reporting.

## Report a vulnerability

Do **not** open a public GitHub issue for a vulnerability in this engine,
Action, or published wheel.

Use GitHub private vulnerability reporting:

https://github.com/thulisa-n/pki-compliance-gate/security/advisories/new

Include the engine version (`pki-gate --version`), the policy file, a
minimized PEM or CSR if you can share one, and the report JSON (redact hostnames
if needed).

We will acknowledge the report and tell you whether we can use the sample in a
regression test.

## False positives

A control that fires on a certificate you believe is policy-correct is not a
vulnerability. File a public issue with the false-positive template.
