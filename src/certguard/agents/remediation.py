from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class RemediationAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="remediation_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report = context.get("report")
        if not isinstance(report, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Remediation requires a report dictionary input."],
            )

        checks = report.get("checks", [])
        if not isinstance(checks, list):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Compliance report is missing a valid 'checks' list."],
            )

        failed = [item for item in checks if item.get("status") == "fail"]
        actions: list[dict[str, str]] = []
        remediation_checks: list[CheckResult] = []

        for item in failed:
            check_name = item.get("name", "unknown_check")
            action = self._action_for_check(check_name)
            actions.append(
                {
                    "check": check_name,
                    "action_type": action["action_type"],
                    "step": action["step"],
                    "owner": action["owner"],
                }
            )
            remediation_checks.append(
                CheckResult(
                    name=f"remediate_{check_name}",
                    status="pass" if action["action_type"] == "automated" else "fail",
                    details=action["step"],
                )
            )

        summary = {
            "failed_count": len(failed),
            "actions": actions,
            "automated_actions": len(
                [entry for entry in actions if entry["action_type"] == "automated"]
            ),
            "manual_actions": len(
                [entry for entry in actions if entry["action_type"] == "manual"]
            ),
            "next_action": (
                "Apply proposed remediations and run heal mode with a corrected certificate."
                if failed
                else "No remediation required."
            ),
        }

        return AgentResult(
            agent=self.name,
            success=len(failed) == 0,
            checks=remediation_checks,
            data=summary,
        )

    def _action_for_check(self, check_name: str) -> dict[str, str]:
        mapping = {
            "signature_algorithm": {
                "action_type": "manual",
                "step": "Reissue certificate using SHA-256 or stronger signature algorithm.",
                "owner": "certificate_operations",
            },
            "rsa_key_size": {
                "action_type": "manual",
                "step": "Generate a new RSA key pair with minimum 2048-bit key size.",
                "owner": "certificate_operations",
            },
            "internal_domain_check": {
                "action_type": "manual",
                "step": "Replace internal SAN domains with publicly trusted DNS names.",
                "owner": "application_owner",
            },
            "san_extension": {
                "action_type": "manual",
                "step": "Reissue certificate with SAN extension populated per host inventory.",
                "owner": "certificate_operations",
            },
            "validity_days": {
                "action_type": "manual",
                "step": "Reissue certificate with validity at or below policy threshold.",
                "owner": "certificate_operations",
            },
        }
        return mapping.get(
            check_name,
            {
                "action_type": "manual",
                "step": "Review failed control and map remediation to certificate profile updates.",
                "owner": "security_engineering",
            },
        )
