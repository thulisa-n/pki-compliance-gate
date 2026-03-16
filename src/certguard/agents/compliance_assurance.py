from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class ComplianceAssuranceAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="compliance_assurance_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report = context.get("report")
        if not isinstance(report, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Assurance requires a report dictionary input."],
            )

        checks = report.get("checks", [])
        if not isinstance(checks, list):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Compliance report is missing a valid 'checks' list."],
            )

        required_controls = context.get(
            "required_controls",
            [
                "validity_days",
                "san_extension",
                "rsa_key_size",
                "signature_algorithm",
                "internal_domain_check",
            ],
        )

        check_map = {item.get("name"): item.get("status") for item in checks}
        assurance_checks: list[CheckResult] = []

        for control in required_controls:
            if control not in check_map:
                assurance_checks.append(
                    CheckResult(
                        name=f"assure_{control}",
                        status="fail",
                        details="Required control not present in report.",
                    )
                )
                continue

            status = "pass" if check_map[control] == "pass" else "fail"
            details = (
                "Control is present and passing."
                if status == "pass"
                else "Control is present but failing."
            )
            assurance_checks.append(
                CheckResult(name=f"assure_{control}", status=status, details=details)
            )

        report_compliant = bool(report.get("compliant"))
        assurance_checks.append(
            CheckResult(
                name="assure_final_compliance_flag",
                status="pass" if report_compliant else "fail",
                details="Final compliance flag is aligned."
                if report_compliant
                else "Final compliance flag indicates non-compliance.",
            )
        )

        success = all(item.status == "pass" for item in assurance_checks)
        return AgentResult(
            agent=self.name,
            success=success,
            checks=assurance_checks,
            data={
                "required_controls": required_controls,
                "controls_verified": len(required_controls),
            },
        )
