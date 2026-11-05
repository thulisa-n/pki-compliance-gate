# Branch protection for `main`

These settings are applied by a repository admin in GitHub. This repository
does not change them. Until they are on, a red check is visible but does not
block the merge button.

Open **Settings → Rules → Rulesets** (or **Settings → Branches**) for `main`.

## Protected `main`

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Block force pushes.
- Block deletions.
- Do not allow bypassing the rule, including for administrators.

## Required checks

Require every check below. A red one blocks the merge.

| Check | Workflow | What it gates |
| --- | --- | --- |
| `ruff` | Code Quality | Ruff lint, first and fastest |
| `gitleaks` | Secret Detection | Secret scan |
| `quality` | Code Quality | Unit tests and coverage floor |
| `fixture-matrix` | Code Quality | Real certificate fixtures through the `neakam` CLI |
| `strict-profile-smoke` | Code Quality | Strict profile through the `neakam` CLI |
| `sast-and-deps` | Security Scans | Bandit and pip-audit, medium and above |
| `run-compliance` | Compliance Gate | Engine run, zlint, OPA, SBOM |
| `analyze` | CodeQL | Code scanning. The matrix may show as `analyze (python)` |
| `wheel-smoke` | Distribution Contract | Wheel install and `neakam doctor` |
| `action-smoke` | Distribution Contract | Composite Action |

`standards-pr-guard` and `docs-render` run only when their paths change. Require
them as well if the ruleset can mark a check required only when it reports.

Secret Detection, Security Scans, and CodeQL start with the test chain so a
green pull request is not stuck behind a serial scan. Code Quality still orders
ruff, then unit tests, then the fixture jobs.

## Squash merges

- Allow squash merging.
- Disable merge commits and rebase merges so `main` stays a linear history.
- The auto-merge workflow for Dependabot and the standards-sync pull request
  already requests squash.

## Signed commits

- Require signed commits on `main`.
- This is a cryptographic signature (SSH or GPG), separate from the
  `Signed-off-by` trailer required by the Developer Certificate of Origin.

## What this change does not do

No workflow in this repository calls the branch-protection API. After the pull
request is green, apply the settings above and confirm the required-check names
match the checks GitHub shows on that pull request.
