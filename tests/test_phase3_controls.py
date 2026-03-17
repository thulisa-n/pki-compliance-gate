from __future__ import annotations

import json
from pathlib import Path

import pytest

from certguard.agents.reviewer_summary import ReviewerSummaryAgent
from certguard.governance import ProtectedRunError, enforce_protected_context


def test_protected_context_requires_github_actions() -> None:
    with pytest.raises(ProtectedRunError, match="GitHub Actions"):
        enforce_protected_context({"GITHUB_ACTIONS": "false"})


def test_protected_context_requires_protected_ref() -> None:
    with pytest.raises(ProtectedRunError, match="protected branch"):
        enforce_protected_context(
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REF_PROTECTED": "false",
                "GITHUB_ACTOR": "thulisa-n",
            }
        )


def test_protected_context_passes_with_required_env() -> None:
    enforce_protected_context(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTOR": "thulisa-n",
        }
    )


def test_reviewer_summary_agent_writes_markdown(tmp_path: Path) -> None:
    report = {
        "certificate": "tests/certificates/valid_cert.pem",
        "generated_at": "2026-03-16T20:00:00+00:00",
        "compliant": True,
        "checks": [{"name": "validity_days", "status": "pass", "details": "ok"}],
        "lint": {"status": "skipped"},
    }
    output_path = tmp_path / "compliance_summary.md"
    result = ReviewerSummaryAgent().run(
        {"report": report, "output_path": str(output_path)}
    )

    assert result.success is True
    content = output_path.read_text(encoding="utf-8")
    assert "Compliance Summary" in content
    assert "COMPLIANT" in content
    assert "validity_days" in content
