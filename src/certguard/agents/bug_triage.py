from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class BugTriageAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="bug_triage_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        report = context.get("report")
        if not isinstance(report, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Bug triage requires a report dictionary input."],
            )

        checks = report.get("checks", [])
        if not isinstance(checks, list):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Compliance report is missing a valid 'checks' list."],
            )

        failed = [item for item in checks if item.get("status") == "fail"]
        triage_checks: list[CheckResult] = []
        findings: list[dict[str, str]] = []

        for check in failed:
            check_name = check.get("name", "unknown_check")
            severity, recommendation = self._classify(check_name)
            findings.append(
                {
                    "check": check_name,
                    "severity": severity,
                    "details": check.get("details", ""),
                    "recommendation": recommendation,
                }
            )
            triage_checks.append(
                CheckResult(
                    name=f"triage_{check_name}",
                    status="fail",
                    details=f"{severity.upper()}: {recommendation}",
                )
            )

        overall = self._overall_severity(findings)
        summary = {
            "failed_count": len(failed),
            "overall_severity": overall,
            "findings": findings,
            "next_action": self._next_action(overall),
        }

        return AgentResult(
            agent=self.name,
            success=len(failed) == 0,
            checks=triage_checks,
            data=summary,
        )

    def _classify(self, check_name: str) -> tuple[str, str]:
        severity_map = {
            "signature_algorithm": (
                "critical",
                "Rotate to SHA-256+ signature profile and regenerate certificate.",
            ),
            "rsa_key_size": (
                "critical",
                "Regenerate key material with RSA 2048+ and re-issue certificate.",
            ),
            "internal_domain_check": (
                "high",
                "Replace internal SAN entries with publicly valid DNS names.",
            ),
            "san_extension": (
                "high",
                "Reissue certificate with SAN extension populated per DNS profile.",
            ),
            "validity_days": (
                "medium",
                "Reduce validity period to meet policy threshold.",
            ),
        }
        return severity_map.get(
            check_name,
            ("medium", "Review policy mapping and certificate profile for this check."),
        )

    def _overall_severity(self, findings: list[dict[str, str]]) -> str:
        if not findings:
            return "none"
        order = ["critical", "high", "medium", "low"]
        severities = {item["severity"] for item in findings}
        for value in order:
            if value in severities:
                return value
        return "medium"

    def _next_action(self, severity: str) -> str:
        actions = {
            "critical": "Block release and open urgent remediation issue.",
            "high": "Require remediation before merge.",
            "medium": "Fix in current sprint and re-run assurance checks.",
            "low": "Track in backlog and monitor trend.",
            "none": "No triage action required.",
        }
        return actions.get(severity, "Review findings with security owner.")
