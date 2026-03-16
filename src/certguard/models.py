from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    name: str
    status: str
    details: str

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

    @classmethod
    def new(
        cls,
        certificate: str,
        compliant: bool,
        checks: list[CheckResult],
        parser_data: dict[str, Any],
        lint: dict[str, Any],
    ) -> "ComplianceReport":
        return cls(
            certificate=certificate,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compliant=compliant,
            checks=checks,
            parser_data=parser_data,
            lint=lint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate": self.certificate,
            "generated_at": self.generated_at,
            "compliant": self.compliant,
            "checks": [check.to_dict() for check in self.checks],
            "parser_data": self.parser_data,
            "lint": self.lint,
        }
