from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class EvidenceVaultAgent(BaseAgent):
    """Seal evidence files with immutable SHA-256 fingerprint metadata."""

    def __init__(self) -> None:
        super().__init__(name="evidence_vault_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report_path_raw = context.get("report_path")
        if not report_path_raw:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Evidence sealing requires 'report_path' in context."],
            )

        report_path = Path(str(report_path_raw))
        if not report_path.exists():
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[f"Report file not found for sealing: {report_path}"],
            )

        seal_path = context.get("seal_path")
        seal_file = (
            Path(str(seal_path))
            if seal_path
            else report_path.with_suffix(report_path.suffix + ".seal")
        )
        seal_file.parent.mkdir(parents=True, exist_ok=True)

        fingerprint = hashlib.sha256(report_path.read_bytes()).hexdigest()
        manifest = {
            "evidence_file": report_path.name,
            "sha256_fingerprint": fingerprint,
            "sealed_at": datetime.now(timezone.utc).isoformat(),
            "environment": os.getenv("GITHUB_WORKFLOW", "local-dev"),
            "actor": os.getenv("GITHUB_ACTOR", "manual-run"),
            "run_id": os.getenv("GITHUB_RUN_ID", "local-run"),
            "commit_sha": os.getenv("GITHUB_SHA", "local-commit"),
            "git_ref": os.getenv("GITHUB_REF", "local-ref"),
        }
        seal_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return AgentResult(
            agent=self.name,
            success=True,
            checks=[
                CheckResult(
                    name="evidence_seal",
                    status="pass",
                    details=f"Report sealed at {seal_file} with SHA-256 fingerprint.",
                )
            ],
            data={"seal_path": str(seal_file), "fingerprint": fingerprint},
        )
