from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    name: str
    status: str
    details: str
    rule_id: str | None = None
    category: str | None = None
    severity: str | None = None
    standard_reference: str | None = None
    policy_value: Any = None
    actual_value: Any = None
    rationale: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentResult:
    agent: str
    success: bool
    checks: list[CheckResult] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "success": self.success,
            "checks": [check.to_dict() for check in self.checks],
            "data": self.data,
            "errors": self.errors,
        }


@dataclass
class ComplianceReport:
    certificate: str
    generated_at: str
    compliant: bool
    checks: list[CheckResult]
    parser_data: dict[str, Any]
    lint: dict[str, Any]
    score: float
    risk_level: str
    failed_controls: list[dict[str, Any]]
    policy_version: str

    @classmethod
    def new(
        cls,
        certificate: str,
        compliant: bool,
        checks: list[CheckResult],
        parser_data: dict[str, Any],
        lint: dict[str, Any],
        policy_version: str,
    ) -> "ComplianceReport":
        failed_controls = [
            {
                "name": check.name,
                "rule_id": check.rule_id,
                "severity": (check.severity or "unknown").lower(),
                "standard_reference": check.standard_reference,
            }
            for check in checks
            if check.status == "fail"
        ]
        total_checks = len(checks)
        passed_checks = len([check for check in checks if check.status == "pass"])
        score = round((passed_checks / total_checks) * 100, 2) if total_checks else 0.0
        risk_level = _risk_from_failed_controls(failed_controls)
        return cls(
            certificate=certificate,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compliant=compliant,
            checks=checks,
            parser_data=parser_data,
            lint=lint,
            score=score,
            risk_level=risk_level,
            failed_controls=failed_controls,
            policy_version=policy_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate": self.certificate,
            "generated_at": self.generated_at,
            "compliant": self.compliant,
            "checks": [check.to_dict() for check in self.checks],
            "parser_data": self.parser_data,
            "lint": self.lint,
            "score": self.score,
            "risk_level": self.risk_level,
            "failed_controls": self.failed_controls,
            "policy_version": self.policy_version,
        }


def _risk_from_failed_controls(failed_controls: list[dict[str, Any]]) -> str:
    severities = {item.get("severity", "unknown") for item in failed_controls}
    if "critical" in severities:
        return "HIGH"
    if "high" in severities or "medium" in severities:
        return "MEDIUM"
    if "low" in severities:
        return "LOW"
    return "LOW"
