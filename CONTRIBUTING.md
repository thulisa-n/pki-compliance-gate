# Contributing

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Locked dependencies

Runtime and development dependencies are hash-pinned in `requirements.txt` and
`requirements-dev.txt`. CI installs those files with
`pip install --require-hashes` and does not `pip install` a package by name.

After editing `pyproject.toml`, regenerate both files with Python 3.11 and
commit them:

```bash
pip install pip-tools
bash scripts/update_lockfile.sh
```

Dependabot (`.github/dependabot.yml`) opens weekly pull requests for those pip
files and for GitHub Actions pinned to a commit SHA.

## Run Tests

```bash
pytest -q
pytest tests/test_verdict_corpus.py -q
```

The corpus in `corpus/verdicts.yaml` is the published expected-verdict contract.

## Security reports

Vulnerabilities go through [SECURITY.md](SECURITY.md), not a public issue.

## Run Core Flows Locally

Evaluate:

```bash
neakam --cert tests/certificates/valid_cert.pem
neakam doctor
```

`pki-gate` and `certguard` still run and print a deprecation notice.

Watch:

```bash
neakam --mode watch \
  --policy policies/cabf_policy.yaml \
  --standards-baseline policies/standards_baseline.yaml
```

API TLS posture (opt-in; no other mode uses the network):

```bash
neakam --mode apisec --allow-network --endpoint https://example.com
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

## Repository boundary

Paid or proprietary content is out of scope for this repository. Work starts
from `origin/main` on a `public/*` branch and is pushed only to the `origin`
remote.

Do not add these paths, or code that belongs only with them:

- `src/certguard_enterprise/`
- `requirements-enterprise.txt`
- API and document-publisher tests
- customer, tenant, billing, hosted-service, or proprietary workflow code

The repository-boundary test fails CI if those paths, their imports, or the
framework dependencies they imply appear in this repository.

## CI Workflow Inventory

Gates run fastest first inside Code Quality: ruff, then unit tests, then the
neakam fixture jobs. Secret detection and Bandit/pip-audit start immediately in
their own workflows. Branch protection settings are in
[docs/BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md).

- `code-quality.yml`
- `secrets-scan.yml`
- `security-scans.yml`
- `compliance.yml`
- `codeql.yml`
- `distribution.yml`
- `standards-sync.yml`
- `standards-pr-guard.yml`
- `docs-render.yml`

## Automation Secrets

- `STANDARDS_SYNC_PR_TOKEN`: required by `standards-sync.yml` to open the review
  pull request when the Baseline Requirements digest changes. The workflow does
  not fall back to `github.token`. If the secret is missing, or the change has
  no review pull request, the job writes a summary and fails. Snapshots still
  include `sync.fetched_at`, which `standards-pr-guard.yml` requires.
