from __future__ import annotations

from pathlib import Path
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import SEVERITY_ORDER, AgentResult, CheckResult


def _format_findings(findings: Any) -> str:
    if not isinstance(findings, dict):
        return "unavailable"
    parts = [
        f"{severity}={findings.get(severity, 0)}"
        for severity in SEVERITY_ORDER
        if findings.get(severity)
    ]
    return ", ".join(parts) if parts else "none"


def _format_coverage(coverage: Any) -> str:
    if not isinstance(coverage, dict):
        return "unavailable"
    return (
        f"{coverage.get('controls_evaluated', 0)} of "
        f"{coverage.get('controls_defined', 0)} controls evaluated, "
        f"{coverage.get('not_applicable', 0)} not applicable"
    )


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
            f"- Risk Level: `{report.get('risk_level', 'unknown')}`",
            f"- Findings: `{_format_findings(report.get('findings'))}`",
            f"- Coverage: `{_format_coverage(report.get('coverage'))}`",
            "",
            "## Check Results",
            "",
        ]

        # Human-readable result labels; "PASS" is not a credential.
        labels = {
            "pass": "PASS",  # nosec B105
            "fail": "FAIL",
            "waived": "WAIVED",
            "not_applicable": "N/A",
        }
        for item in checks:
            raw_status = str(item.get("status", "unknown")).strip().lower()
            # Previously anything that was not "pass" rendered as FAIL, so a
            # control the policy never enabled looked like a defect.
            label = labels.get(raw_status, raw_status.upper() or "UNKNOWN")
            lines.append(
                f"- [{label}] `{item.get('name', 'unknown_check')}`: {item.get('details', '')}"
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
