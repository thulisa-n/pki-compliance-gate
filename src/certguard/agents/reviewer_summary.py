from __future__ import annotations

from pathlib import Path
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class ReviewerSummaryAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="reviewer_summary_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report = context.get("report")
        output_path_raw = context.get("output_path")

        if not isinstance(report, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Reviewer summary requires a report dictionary input."],
            )
        if not output_path_raw:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Reviewer summary requires an output_path value."],
            )

        output_path = Path(str(output_path_raw))
        output_path.parent.mkdir(parents=True, exist_ok=True)

        checks = report.get("checks", [])
        compliant = bool(report.get("compliant"))
        cert = report.get("certificate", "unknown")
        generated_at = report.get("generated_at", "unknown")
        lint_status = (report.get("lint") or {}).get("status", "unknown")

        lines = [
            "# Compliance Summary",
            "",
            f"- Certificate: `{cert}`",
            f"- Generated At: `{generated_at}`",
            f"- Final Result: `{'COMPLIANT' if compliant else 'NON-COMPLIANT'}`",
            f"- Lint Status: `{lint_status}`",
            "",
            "## Check Results",
            "",
        ]

        for item in checks:
            status = item.get("status", "unknown").upper()
            icon = "PASS" if status == "PASS" else "FAIL"
            lines.append(
                f"- [{icon}] `{item.get('name', 'unknown_check')}`: {item.get('details', '')}"
            )

        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        return AgentResult(
            agent=self.name,
            success=True,
            checks=[
                CheckResult(
                    name="reviewer_summary_generation",
                    status="pass",
                    details=f"Reviewer summary written to {output_path}",
                )
            ],
            data={"summary_path": str(output_path)},
        )
