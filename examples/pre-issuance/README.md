# Pre-issuance gate

`pki-gate --csr` evaluates a PEM certificate signing request against the same
YAML policy as issued certificates, but only for facts that exist on a CSR:

- SAN present / internal DNS suffixes
- key algorithm, RSA/EC size, approved curves
- CSR proof-of-possession signature hash and OID

Validity window, serial entropy, SCT, EKU, and RFC 5280 path profile are
recorded as `not_applicable`. Guessing them would be a false pass.

This is a **thin** hook: drop it in front of the signer. It is not a
cert-manager admission webhook.

## CLI

```bash
pki-gate --csr incoming.csr --policy policies/cabf_policy.yaml
```

## GitHub Action

See `github-action.yml` in this directory. Point `csr` at a PEM in the
caller workspace.

## step-ca / local CA

```bash
pki-gate --csr request.csr
status=$?
if [ "$status" -ne 0 ]; then
  echo "policy rejected the CSR (exit $status)" >&2
  exit "$status"
fi
step ca sign request.csr issued.crt
pki-gate --cert issued.crt
```

## cert-manager

Keep CSRs (or issued PEMs) in git or fetch them in CI, then run the Action.
An in-cluster webhook is out of scope for this release. A Job that shells out
to `pki-gate --csr` after `kubectl get certificaterequest -o json` is a
reasonable next step in a private cluster; do not copy that as a public
admission controller without reviewing RBAC and fail-closed behaviour.
