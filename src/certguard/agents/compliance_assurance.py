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
        check_map = self._normalize_checks(checks)
        if check_map is None:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[
                    "Compliance report contains malformed or duplicate checks; assurance "
                    "requires unique check names and string statuses."
                ],
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

        report_compliant = report.get("compliant")
        if not isinstance(report_compliant, bool):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Compliance report 'compliant' flag must be a boolean value."],
            )
        lint_status = self._extract_lint_status(report.get("lint"))
        expected_compliant = ("fail" not in set(check_map.values())) and lint_status != "fail"
        assurance_checks.append(
            CheckResult(
                name="assure_final_compliance_flag",
                status="pass" if report_compliant == expected_compliant else "fail",
                details=(
                    f"Final compliance flag matches independently recomputed outcome "
                    f"({expected_compliant})."
                    if report_compliant == expected_compliant
                    else f"Final compliance flag mismatch: report={report_compliant}, "
                    f"recomputed={expected_compliant}."
                ),
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

    def _normalize_checks(self, checks: list[Any]) -> dict[str, str] | None:
        allowed_statuses = {"pass", "fail", "waived"}
        normalized: dict[str, str] = {}
        for item in checks:
            if not isinstance(item, dict):
                return None
            name = item.get("name")
            status = item.get("status")
            if not isinstance(name, str) or not name.strip():
                return None
            if not isinstance(status, str):
                return None
            normalized_status = status.strip().lower()
            if normalized_status not in allowed_statuses:
                return None
            if name in normalized:
                return None
            normalized[name] = normalized_status
        return normalized

    def _extract_lint_status(self, lint: Any) -> str | None:
        if not isinstance(lint, dict):
            return None
        status = lint.get("status")
        if not isinstance(status, str):
            return None
        return status.strip().lower()
