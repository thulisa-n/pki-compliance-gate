# Contributing

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Run Tests

```bash
pytest -q
```

## Run Core Flows Locally

Evaluate:

```bash
pki-gate --cert tests/certificates/valid_cert.pem
```

Watch:

```bash
pki-gate --mode watch \
  --policy policies/cabf_policy.yaml \
  --standards-baseline policies/standards_baseline.yaml
```

API TLS posture:

```bash
pki-gate --mode apisec --endpoint https://example.com
```

## Developer Certificate of Origin

This project requires a Developer Certificate of Origin on every commit.
Add a `Signed-off-by: Your Name <you@example.com>` trailer that matches the
commit author, typically with `git commit -s`.

By contributing you certify [DCO 1.1](https://developercertificate.org/).

## Pull Request Expectations

- Keep PRs scoped to one change theme.
- Include or update tests for behavior changes.
- Keep docs aligned with runtime behavior (CLI flags, exit codes, workflow names).
- Ensure GitHub Actions checks are green before merge.

## Public and enterprise boundary

This repository is the open-source core. Core work starts from `origin/main` on
a `public/*` branch and is pushed only to the `origin` remote. The private
enterprise repository may merge or cherry-pick reviewed public commits.

Do not push these commercial surfaces to the public remote:

- `src/certguard_enterprise/`
- `requirements-enterprise.txt`
- enterprise API and document-publisher tests
- customer, tenant, billing, hosted-service, or proprietary workflow code

The repository-boundary test fails public CI if known enterprise paths or
framework dependencies reappear. If a feature is useful to both editions,
implement its generic contract in public first and add commercial orchestration
in the private namespace.

## CI Workflow Inventory

- `compliance.yml`
- `security-scans.yml`
- `codeql.yml`
- `secrets-scan.yml`
- `iac-scan.yml`
- `standards-sync.yml`
- `standards-pr-guard.yml`
- `kyverno-policy.yml`
- `docs-render.yml`

## Automation Secrets

- `STANDARDS_SYNC_PR_TOKEN`: token used by `standards-sync.yml` when creating bot PRs.
  Configure this secret so downstream PR workflows (`Compliance Gate`, `Security Scans`)
  auto-trigger on standards-sync pull requests.
