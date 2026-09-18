from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from certguard import REPORT_SCHEMA_VERSION, __version__

#: A control either passed, failed, was waived by an approved exception, or was
#: never evaluated because policy did not enable it.
#:
#: ``not_applicable`` exists so that an evidence artefact never claims a control
#: passed on a run where it was not assessed. Prior to report schema 2.0 these
#: were recorded as ``pass``, which inflated results and misrepresented the
#: evidence to a reviewer.
Status = Literal["pass", "fail", "waived", "not_applicable"]

VALID_STATUSES: frozenset[str] = frozenset({"pass", "fail", "waived", "not_applicable"})

#: Ordered most to least serious. Used for risk derivation and report ordering.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")


@dataclass
class CheckResult:
    name: str
    status: Status
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

    def normalized_severity(self) -> str:
        value = (self.severity or "unknown").strip().lower()
        return value if value in SEVERITY_ORDER else "unknown"

    def replace_status(self, status: Status, details: str) -> "CheckResult":
        """Return a copy with a new status, leaving the original untouched.

        Waiver application uses this rather than mutating in place, so the
        result returned by an agent is never retroactively rewritten.
        """
        clone = CheckResult(**asdict(self))
        clone.status = status
        clone.details = details
        return clone


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
    """A single certificate evaluation.

    Report schema 2.0 deliberately carries no single percentage score. A
    percentage invited two misreadings that a compliance artefact cannot
    afford: controls disabled by policy counted as passes (so an almost-empty
    profile read 100%), and a certificate failing a *critical* control could
    still present as ~95% because most controls happened to pass. Findings are
    reported by severity, and coverage is reported separately, so a reviewer can
    see both what failed and how much was actually assessed.
    """

    certificate: str
    generated_at: str
    compliant: bool
    checks: list[CheckResult]
    parser_data: dict[str, Any]
    lint: dict[str, Any]
    risk_level: str
    findings: dict[str, int]
    coverage: dict[str, int]
    failed_controls: list[dict[str, Any]]
    waived_controls: list[dict[str, Any]]
    policy_version: str
    engine_version: str = __version__
    report_schema_version: str = REPORT_SCHEMA_VERSION
    input_kind: str = "certificate"
    evaluated_at: str | None = None
    verdict_digest: str | None = None

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
            _control_summary(check) for check in checks if check.status == "fail"
        ]
        waived_controls = [
            _control_summary(check) for check in checks if check.status == "waived"
        ]

        findings = {severity: 0 for severity in SEVERITY_ORDER}
        for check in checks:
            if check.status == "fail":
                findings[check.normalized_severity()] += 1

        coverage = {
            "controls_defined": len(checks),
            "controls_evaluated": len(
                [c for c in checks if c.status in {"pass", "fail", "waived"}]
            ),
            "passed": len([c for c in checks if c.status == "pass"]),
            "failed": len([c for c in checks if c.status == "fail"]),
            "waived": len([c for c in checks if c.status == "waived"]),
            "not_applicable": len([c for c in checks if c.status == "not_applicable"]),
        }

        evaluated_at = parser_data.get("evaluated_at")
        if isinstance(evaluated_at, str) and evaluated_at:
            generated_at = evaluated_at
        else:
            generated_at = datetime.now(timezone.utc).isoformat()
        input_kind = str(parser_data.get("input_kind") or "certificate")
        report = cls(
            certificate=certificate,
            generated_at=generated_at,
            evaluated_at=evaluated_at if isinstance(evaluated_at, str) else None,
            input_kind=input_kind,
            compliant=compliant,
            checks=checks,
            parser_data=parser_data,
            lint=lint,
            risk_level=risk_level_for(
                failed_controls=failed_controls,
                waived_controls=waived_controls,
                lint_status=str(lint.get("status", "unknown")),
            ),
            findings=findings,
            coverage=coverage,
            failed_controls=failed_controls,
            waived_controls=waived_controls,
            policy_version=policy_version,
        )
        from certguard.verdict import verdict_digest

        report.verdict_digest = verdict_digest(report)
        return report

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_schema_version": self.report_schema_version,
            "engine_version": self.engine_version,
            "certificate": self.certificate,
            "input_kind": self.input_kind,
            "generated_at": self.generated_at,
            "evaluated_at": self.evaluated_at,
            "verdict_digest": self.verdict_digest,
            "compliant": self.compliant,
            "risk_level": self.risk_level,
            "findings": self.findings,
            "coverage": self.coverage,
            "checks": [check.to_dict() for check in self.checks],
            "parser_data": self.parser_data,
            "lint": self.lint,
            "failed_controls": self.failed_controls,
            "waived_controls": self.waived_controls,
            "policy_version": self.policy_version,
        }

    def has_failures(self) -> bool:
        return any(check.status == "fail" for check in self.checks)


def _control_summary(check: CheckResult) -> dict[str, Any]:
    return {
        "name": check.name,
        "rule_id": check.rule_id,
        "severity": check.normalized_severity(),
        "standard_reference": check.standard_reference,
    }


def risk_level_for(
    failed_controls: list[dict[str, Any]],
    waived_controls: list[dict[str, Any]],
    lint_status: str,
) -> str:
    """Derive a risk level from failures, waivers, and lint outcome.

    A waiver suppresses the *gate* (the pipeline is allowed to continue) but it
    must never suppress the *risk statement*: the underlying weakness is still
    present in the certificate. A waived critical finding therefore still yields
    HIGH. Lint failure contributes at least MEDIUM, since previously a
    lint-only failure reported LOW while the certificate was non-compliant.
    """
    severities = {item.get("severity", "unknown") for item in failed_controls}
    severities |= {item.get("severity", "unknown") for item in waived_controls}

    if "critical" in severities:
        return "HIGH"
    if "high" in severities or "medium" in severities:
        return "MEDIUM"
    if lint_status.strip().lower() == "fail":
        return "MEDIUM"
    if "low" in severities or "unknown" in severities:
        return "LOW"
    return "LOW"
