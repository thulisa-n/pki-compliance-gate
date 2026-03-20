from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class TrendSnapshotAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="trend_snapshot_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report = context.get("report")
        output_path_raw = context.get("output_path")
        run_id = context.get("run_id", "local-run")
        trigger = context.get("trigger", "manual")

        if not isinstance(report, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Trend snapshot requires report dictionary input."],
            )
        if not output_path_raw:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Trend snapshot requires output_path."],
            )

        checks = report.get("checks", [])
        passed = len([item for item in checks if item.get("status") == "pass"])
        failed = len([item for item in checks if item.get("status") == "fail"])
        total = len(checks)

        snapshot = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "trigger": trigger,
            "certificate": report.get("certificate"),
            "compliant": bool(report.get("compliant")),
            "score": report.get("score"),
            "risk_level": report.get("risk_level"),
            "counts": {"total": total, "passed": passed, "failed": failed},
        }

        output_path = Path(str(output_path_raw))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

        return AgentResult(
            agent=self.name,
            success=True,
            checks=[
                CheckResult(
                    name="trend_snapshot_generation",
                    status="pass",
                    details=f"Trend snapshot written to {output_path}",
                )
            ],
            data={"snapshot_path": str(output_path)},
        )
