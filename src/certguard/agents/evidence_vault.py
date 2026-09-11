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
    """Record a SHA-256 digest of the compliance report alongside run context.

    This detects accidental change and single-file tampering. It is NOT a
    signature: anyone able to rewrite the report can recompute the digest.
    Tamper-evident custody comes from signing the evidence manifest or from
    the cosign keyless signature produced in CI.
    """

    def __init__(self) -> None:
        super().__init__(name="evidence_vault_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report_path_raw = context.get("report_path")
        if not report_path_raw:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Evidence digest requires 'report_path' in context."],
            )

        report_path = Path(str(report_path_raw))
        if not report_path.exists():
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[f"Report file not found for digest: {report_path}"],
            )

        digest_path = context.get("digest_path")
        digest_file = (
            Path(str(digest_path))
            if digest_path
            else report_path.with_suffix(report_path.suffix + ".digest")
        )
        digest_file.parent.mkdir(parents=True, exist_ok=True)

        fingerprint = hashlib.sha256(report_path.read_bytes()).hexdigest()
        manifest = {
            "evidence_file": report_path.name,
            "sha256_fingerprint": fingerprint,
            "integrity_note": "SHA-256 digest, not a signature.",
            "digest_recorded_at": datetime.now(timezone.utc).isoformat(),
            "environment": os.getenv("GITHUB_WORKFLOW", "local-dev"),
            "actor": os.getenv("GITHUB_ACTOR", "manual-run"),
            "run_id": os.getenv("GITHUB_RUN_ID", "local-run"),
            "commit_sha": os.getenv("GITHUB_SHA", "local-commit"),
            "git_ref": os.getenv("GITHUB_REF", "local-ref"),
        }
        digest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        # Legacy alias for pipelines that still look for `.seal`.
        legacy_seal = report_path.with_suffix(report_path.suffix + ".seal")
        if legacy_seal != digest_file:
            legacy_seal.write_text(digest_file.read_text(encoding="utf-8"), encoding="utf-8")

        return AgentResult(
            agent=self.name,
            success=True,
            checks=[
                CheckResult(
                    name="evidence_digest",
                    status="pass",
                    details=(
                        f"Report digest recorded at {digest_file} "
                        "(SHA-256, not a signature)."
                    ),
                )
            ],
            data={
                "digest_path": str(digest_file),
                "seal_path": str(legacy_seal),
                "fingerprint": fingerprint,
            },
        )
