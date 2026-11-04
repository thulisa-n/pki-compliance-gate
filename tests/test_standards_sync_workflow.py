"""Standards sync must open a real review PR or fail in the open."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

WORKFLOW = Path(".github/workflows/standards-sync.yml")
SECRETS_SCAN = Path(".github/workflows/secrets-scan.yml")
GUARD = Path("scripts/require_standards_review_pr.sh")


def _run_guard(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess[str], str]:
    summary = tmp_path / "summary.md"
    merged = os.environ.copy()
    merged.pop("PR_NUMBER", None)
    merged.pop("PR_URL", None)
    merged.pop("TOKEN_PRESENT", None)
    merged["GITHUB_STEP_SUMMARY"] = str(summary)
    merged.update(env)
    result = subprocess.run(
        ["bash", str(GUARD)],
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )
    text = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return result, text


def test_workflow_never_falls_back_to_the_default_token() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    token_lines = [
        line.strip() for line in workflow.splitlines() if line.strip().startswith("token:")
    ]
    assert token_lines == ["token: ${{ secrets.STANDARDS_SYNC_PR_TOKEN }}"]
    assert "|| github.token" not in workflow
    assert "secrets.GITHUB_TOKEN" not in workflow
    assert "bash scripts/require_standards_review_pr.sh" in workflow
    assert "pull-requests: write" in workflow


def test_gitleaks_workflow_can_read_pull_requests() -> None:
    workflow = SECRETS_SCAN.read_text(encoding="utf-8")
    assert "gitleaks/gitleaks-action@" in workflow
    permissions = workflow.split("permissions:", 1)[1].split("concurrency:", 1)[0]
    assert "pull-requests: read" in permissions
    assert "contents: read" in permissions
    assert "security-events: write" in permissions


def test_review_pull_request_present_is_success(tmp_path: Path) -> None:
    result, summary = _run_guard(
        tmp_path,
        PR_NUMBER="26",
        PR_URL="https://example.test/pull/26",
        TOKEN_PRESENT="false",
    )
    assert result.returncode == 0
    assert "https://example.test/pull/26" in result.stdout
    assert summary == ""
    assert "github.token" not in result.stdout


def test_missing_token_writes_a_summary_and_fails(tmp_path: Path) -> None:
    result, summary = _run_guard(tmp_path, TOKEN_PRESENT="false")
    assert result.returncode == 1
    assert "no review pull request" in summary.lower()
    assert "STANDARDS_SYNC_PR_TOKEN" in summary
    assert "github.token" in summary
    assert "sync.fetched_at" in summary
    assert "was not set" in summary
    assert "ERROR: Baseline Requirements changed" in result.stderr
    assert "does not fall back to github.token" in result.stderr
    assert "STANDARDS_SYNC_PR_TOKEN" not in result.stdout


def test_configured_token_without_a_pull_request_still_fails(tmp_path: Path) -> None:
    result, summary = _run_guard(tmp_path, TOKEN_PRESENT="true", PR_NUMBER="")
    assert result.returncode == 1
    assert "did not get a pull request number" in summary
    assert "github.token" in summary
    assert "sync.fetched_at" in summary
