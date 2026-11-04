#!/usr/bin/env bash
# Fail Standards Sync when a Baseline Requirements change has no review PR.
#
# The workflow calls this after the digest check. It does not create a pull
# request and it never reads github.token or the PAT itself: the caller passes
# TOKEN_PRESENT=true|false and, when a PR exists, PR_NUMBER / PR_URL.
set -euo pipefail

pr_number="${PR_NUMBER:-}"
pr_url="${PR_URL:-}"
token_present="${TOKEN_PRESENT:-false}"

if [ -n "${pr_number}" ]; then
  if [ -n "${pr_url}" ]; then
    echo "Review pull request: ${pr_url}"
  else
    echo "Review pull request #${pr_number}"
  fi
  exit 0
fi

if [ "${token_present}" = "true" ]; then
  cause='`STANDARDS_SYNC_PR_TOKEN` is set, but this run did not get a pull request number back. Check the create-pull-request step and confirm the token can open pull requests on this repository.'
else
  cause='`STANDARDS_SYNC_PR_TOKEN` was not set for this run, so no pull request was opened.'
fi

summary=$(cat <<'EOF'
## Standards sync: no review pull request

The CA/B Forum Baseline Requirements digest changed, but this run did not open or update a review pull request.

This workflow does not fall back to `github.token`. A pull request created with the default token does not trigger Compliance Gate or Security Scans.

### What to do

1. Create a classic or fine-grained personal access token that can open pull requests in this repository.
2. Store it as the Actions secret `STANDARDS_SYNC_PR_TOKEN`.
3. Re-run **Standards Sync** with `workflow_dispatch`.
4. On the review pull request, confirm the hand-maintained dates in `policies/standards_baseline.yaml`. The sync records `sync.fetched_at` and `sync.source_sha256` only. It does not rewrite policy numbers.
EOF
)

summary="${summary}

${cause}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf '%s\n' "${summary}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo "ERROR: Baseline Requirements changed and no review pull request was opened." >&2
echo "Set the STANDARDS_SYNC_PR_TOKEN secret and re-run Standards Sync. This workflow does not fall back to github.token." >&2
echo "${cause}" >&2
exit 1
