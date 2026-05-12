# Contributing

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run Tests

```bash
pytest -q
```

## Run Core Flows Locally

Evaluate:

```bash
python src/main.py --cert tests/certificates/valid_cert.pem
```

Watch:

```bash
python src/main.py --mode watch \
  --policy policies/cabf_policy.yaml \
  --standards-baseline policies/standards_baseline.yaml
```

APITLS posture:

```bash
python src/main.py --mode apisec --endpoint https://example.com
```

## Pull Request Expectations

- Keep PRs scoped to one change theme.
- Include or update tests for behavior changes.
- Keep docs aligned with runtime behavior (CLI flags, exit codes, workflow names).
- Ensure GitHub Actions checks are green before merge.

## CI Workflow Inventory

- `compliance.yml`
- `security-scans.yml`
- `codeql.yml`
- `standards-sync.yml`
- `standards-pr-guard.yml`
- `kyverno-policy.yml`
- `docs-render.yml`
