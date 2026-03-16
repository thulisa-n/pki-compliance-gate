from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class StandardsWatchAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="standards_watch_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        policy = context.get("policy")
        baseline = context.get("baseline")
        if not isinstance(policy, dict) or not isinstance(baseline, dict):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Standards watch requires policy and baseline dictionaries."],
            )

        checks: list[CheckResult] = []
        drifts: list[dict[str, Any]] = []

        expected_validity = self._get_nested(baseline, "expected.certificate.max_validity_days")
        actual_validity = self._get_nested(policy, "certificate.max_validity_days")
        checks.append(
            self._compare_value(
                "max_validity_days",
                actual_validity,
                expected_validity,
                drifts,
            )
        )

        expected_min_rsa = self._get_nested(baseline, "expected.key.minimum_rsa_bits")
        actual_min_rsa = self._get_nested(policy, "key.minimum_rsa_bits")
        checks.append(
            self._compare_value(
                "minimum_rsa_bits",
                actual_min_rsa,
                expected_min_rsa,
                drifts,
            )
        )

        expected_forbidden = self._get_nested(baseline, "expected.signature.prohibited_algorithms")
        actual_forbidden = self._get_nested(policy, "signature.prohibited_algorithms")
        status = "pass" if sorted(actual_forbidden or []) == sorted(expected_forbidden or []) else "fail"
        checks.append(
            CheckResult(
                name="prohibited_algorithms_alignment",
                status=status,
                details="Policy prohibited algorithms aligned with standards baseline."
                if status == "pass"
                else "Policy prohibited algorithms differ from standards baseline.",
            )
        )
        if status == "fail":
            drifts.append(
                {
                    "field": "signature.prohibited_algorithms",
                    "expected": expected_forbidden,
                    "actual": actual_forbidden,
                }
            )

        summary = {
            "baseline_version": self._get_nested(baseline, "baseline.version"),
            "last_reviewed": self._get_nested(baseline, "baseline.last_reviewed"),
            "drift_count": len(drifts),
            "drifts": drifts,
            "recommendation": (
                "Update policy and document standards change impact."
                if drifts
                else "Policy is aligned with tracked standards baseline."
            ),
        }

        return AgentResult(
            agent=self.name,
            success=len(drifts) == 0,
            checks=checks,
            data=summary,
        )

    def _compare_value(
        self, name: str, actual: Any, expected: Any, drifts: list[dict[str, Any]]
    ) -> CheckResult:
        status = "pass" if actual == expected else "fail"
        if status == "fail":
            drifts.append({"field": name, "expected": expected, "actual": actual})
        return CheckResult(
            name=f"{name}_alignment",
            status=status,
            details="Aligned with standards baseline."
            if status == "pass"
            else f"Drift detected. expected={expected}, actual={actual}",
        )

    def _get_nested(self, payload: dict[str, Any], path: str) -> Any:
        current: Any = payload
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
