from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class StandardsWatchAgent(BaseAgent):
    """Compare the active policy against the tracked standards baseline.

    Two things changed here relative to the original implementation. The
    baseline now carries a *dated schedule* (CA/Browser Forum SC-081v3), so the
    comparison is against the phase actually in force rather than a single
    hardcoded number. And the agent reports the *next* phase separately as
    readiness, so an upcoming tightening -- the reduction to 100 days on
    2027-03-15 and to 47 days on 2029-03-15 -- is visible before it lands
    instead of becoming a drift finding the morning after.

    A policy stricter than the standard is not drift. Only a policy that is
    more permissive than the standard is.
    """

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

        as_of = self._resolve_as_of(context.get("as_of"))
        schedule = self._parse_schedule(baseline.get("schedule"))
        active_phase, next_phase = self._phases_for(schedule, as_of)

        checks: list[CheckResult] = []
        drifts: list[dict[str, Any]] = []
        readiness: list[dict[str, Any]] = []

        policy_max_validity = self._get_nested(policy, "certificate.max_validity_days")
        policy_dcv_reuse = self._get_nested(policy, "dcv.max_age_days")

        if active_phase is None:
            checks.append(
                CheckResult(
                    name="standards_schedule_available",
                    status="fail",
                    details=(
                        "Baseline has no schedule phase in force for "
                        f"{as_of.isoformat()}. Add a dated entry to "
                        "policies/standards_baseline.yaml."
                    ),
                )
            )
            drifts.append(
                {
                    "field": "baseline.schedule",
                    "expected": "a phase effective on or before the evaluation date",
                    "actual": None,
                }
            )
        else:
            checks.append(
                self._at_most(
                    "max_validity_days",
                    actual=policy_max_validity,
                    limit=active_phase["max_validity_days"],
                    drifts=drifts,
                    context_note=(
                        f"phase effective {active_phase['effective'].isoformat()}"
                    ),
                )
            )
            checks.append(
                self._at_most(
                    "dcv_reuse_days",
                    actual=policy_dcv_reuse,
                    limit=active_phase["dcv_reuse_days"],
                    drifts=drifts,
                    context_note=(
                        f"phase effective {active_phase['effective'].isoformat()}"
                    ),
                )
            )

        if next_phase is not None:
            for field, actual, limit in (
                ("certificate.max_validity_days", policy_max_validity, next_phase["max_validity_days"]),
                ("dcv.max_age_days", policy_dcv_reuse, next_phase["dcv_reuse_days"]),
            ):
                if isinstance(actual, int) and actual > limit:
                    days_remaining = (next_phase["effective"] - as_of).days
                    readiness.append(
                        {
                            "field": field,
                            "current": actual,
                            "required": limit,
                            "effective": next_phase["effective"].isoformat(),
                            "days_remaining": days_remaining,
                            "action": (
                                f"Reduce {field} to {limit} or lower before "
                                f"{next_phase['effective'].isoformat()}."
                            ),
                        }
                    )
            checks.append(
                CheckResult(
                    name="upcoming_standards_readiness",
                    status="pass" if not readiness else "fail",
                    details=(
                        "Policy already satisfies the next scheduled tightening "
                        f"({next_phase['effective'].isoformat()})."
                        if not readiness
                        else f"{len(readiness)} value(s) exceed the limits taking effect "
                        f"{next_phase['effective'].isoformat()}."
                    ),
                    severity="medium",
                    category="STANDARDS",
                    standard_reference="CA/B Forum Ballot SC-081v3",
                    recommendation=(
                        "Tighten the policy ahead of the effective date, or adopt a "
                        "dated profile that steps down automatically."
                    ),
                )
            )
        else:
            checks.append(
                CheckResult(
                    name="upcoming_standards_readiness",
                    status="not_applicable",
                    details="No later schedule phase is tracked in the baseline.",
                    category="STANDARDS",
                )
            )

        checks.append(
            self._at_least(
                "minimum_rsa_bits",
                actual=self._get_nested(policy, "key.minimum_rsa_bits"),
                floor=self._get_nested(baseline, "expected.key.minimum_rsa_bits"),
                drifts=drifts,
            )
        )
        checks.append(
            self._at_least(
                "minimum_ec_bits",
                actual=self._get_nested(policy, "key.minimum_ec_bits"),
                floor=self._get_nested(baseline, "expected.key.minimum_ec_bits"),
                drifts=drifts,
            )
        )

        checks.append(
            self._superset(
                "prohibited_algorithms",
                actual=self._get_nested(policy, "signature.prohibited_algorithms"),
                required=self._get_nested(
                    baseline, "expected.signature.prohibited_algorithms"
                ),
                drifts=drifts,
            )
        )
        checks.append(
            self._subset(
                "allowed_ec_curves",
                actual=self._get_nested(policy, "key.allowed_ec_curves"),
                permitted=self._get_nested(baseline, "expected.key.allowed_ec_curves"),
                drifts=drifts,
            )
        )

        for field in ("reject_expired", "reject_not_yet_valid"):
            expected = self._get_nested(baseline, f"expected.certificate.{field}")
            actual = self._get_nested(policy, f"certificate.{field}")
            if expected is None:
                continue
            aligned = bool(actual) == bool(expected)
            checks.append(
                CheckResult(
                    name=f"{field}_alignment",
                    status="pass" if aligned else "fail",
                    details=(
                        f"certificate.{field} matches the baseline ({expected})."
                        if aligned
                        else f"certificate.{field} is {actual}; baseline requires {expected}."
                    ),
                    severity="high",
                    category="STANDARDS",
                )
            )
            if not aligned:
                drifts.append(
                    {
                        "field": f"certificate.{field}",
                        "expected": expected,
                        "actual": actual,
                    }
                )

        summary = {
            "as_of": as_of.isoformat(),
            "baseline_version": self._get_nested(baseline, "baseline.version"),
            "baseline_authority": self._get_nested(baseline, "baseline.authority"),
            "last_reviewed": self._get_nested(baseline, "baseline.last_reviewed"),
            "active_phase": self._phase_summary(active_phase),
            "next_phase": self._phase_summary(next_phase),
            "drift_count": len(drifts),
            "drifts": drifts,
            "readiness_gap_count": len(readiness),
            "readiness_gaps": readiness,
            "recommendation": (
                "Update policy and document standards change impact."
                if drifts
                else "Policy is aligned with the standards phase in force."
            ),
        }

        return AgentResult(
            agent=self.name,
            success=len(drifts) == 0,
            checks=checks,
            data=summary,
        )

    # ----------------------------------------------------------------- helpers

    def _resolve_as_of(self, value: Any) -> date:
        if isinstance(value, date) and not isinstance(value, datetime):
            return value
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str) and value.strip():
            return datetime.fromisoformat(value.strip()).date()
        return datetime.now(timezone.utc).date()

    def _parse_schedule(self, raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        phases: list[dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            effective = entry.get("effective")
            if isinstance(effective, date) and not isinstance(effective, datetime):
                effective_date = effective
            elif isinstance(effective, str):
                try:
                    effective_date = datetime.fromisoformat(effective).date()
                except ValueError:
                    continue
            else:
                continue
            max_validity = entry.get("max_validity_days")
            dcv_reuse = entry.get("dcv_reuse_days")
            if not isinstance(max_validity, int) or not isinstance(dcv_reuse, int):
                continue
            phases.append(
                {
                    "effective": effective_date,
                    "max_validity_days": max_validity,
                    "dcv_reuse_days": dcv_reuse,
                    "note": entry.get("note"),
                }
            )
        return sorted(phases, key=lambda item: item["effective"])

    def _phases_for(
        self, schedule: list[dict[str, Any]], as_of: date
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        active: dict[str, Any] | None = None
        upcoming: dict[str, Any] | None = None
        for phase in schedule:
            if phase["effective"] <= as_of:
                active = phase
            elif upcoming is None:
                upcoming = phase
        return active, upcoming

    def _phase_summary(self, phase: dict[str, Any] | None) -> dict[str, Any] | None:
        if phase is None:
            return None
        return {
            "effective": phase["effective"].isoformat(),
            "max_validity_days": phase["max_validity_days"],
            "dcv_reuse_days": phase["dcv_reuse_days"],
            "note": phase.get("note"),
        }

    def _at_most(
        self,
        name: str,
        actual: Any,
        limit: Any,
        drifts: list[dict[str, Any]],
        context_note: str = "",
    ) -> CheckResult:
        suffix = f" ({context_note})" if context_note else ""
        if not isinstance(actual, int) or not isinstance(limit, int):
            drifts.append({"field": name, "expected": limit, "actual": actual})
            return CheckResult(
                name=f"{name}_alignment",
                status="fail",
                details=f"Cannot compare {name}: expected={limit}, actual={actual}.",
                category="STANDARDS",
            )
        aligned = actual <= limit
        if not aligned:
            drifts.append({"field": name, "expected": f"<= {limit}", "actual": actual})
        return CheckResult(
            name=f"{name}_alignment",
            status="pass" if aligned else "fail",
            details=(
                f"Policy {name}={actual} is within the standard maximum of {limit}{suffix}."
                if aligned
                else f"Policy {name}={actual} exceeds the standard maximum of {limit}{suffix}."
            ),
            severity="high",
            category="STANDARDS",
            standard_reference="CA/B Forum Ballot SC-081v3",
        )

    def _at_least(
        self, name: str, actual: Any, floor: Any, drifts: list[dict[str, Any]]
    ) -> CheckResult:
        if floor is None:
            return CheckResult(
                name=f"{name}_alignment",
                status="not_applicable",
                details=f"Baseline does not specify {name}.",
                category="STANDARDS",
            )
        if not isinstance(actual, int):
            drifts.append({"field": name, "expected": f">= {floor}", "actual": actual})
            return CheckResult(
                name=f"{name}_alignment",
                status="fail",
                details=f"Cannot compare {name}: expected>={floor}, actual={actual}.",
                category="STANDARDS",
            )
        aligned = actual >= floor
        if not aligned:
            drifts.append({"field": name, "expected": f">= {floor}", "actual": actual})
        return CheckResult(
            name=f"{name}_alignment",
            status="pass" if aligned else "fail",
            details=(
                f"Policy {name}={actual} meets the baseline floor of {floor}."
                if aligned
                else f"Policy {name}={actual} is below the baseline floor of {floor}."
            ),
            severity="high",
            category="STANDARDS",
        )

    def _superset(
        self, name: str, actual: Any, required: Any, drifts: list[dict[str, Any]]
    ) -> CheckResult:
        actual_set = {str(v).lower() for v in actual or []}
        required_set = {str(v).lower() for v in required or []}
        missing = sorted(required_set - actual_set)
        if missing:
            drifts.append(
                {
                    "field": f"signature.{name}",
                    "expected": sorted(required_set),
                    "actual": sorted(actual_set),
                }
            )
        return CheckResult(
            name=f"{name}_alignment",
            status="pass" if not missing else "fail",
            details=(
                "Policy prohibits every algorithm the baseline requires."
                if not missing
                else f"Policy does not prohibit: {', '.join(missing)}."
            ),
            severity="critical",
            category="STANDARDS",
        )

    def _subset(
        self, name: str, actual: Any, permitted: Any, drifts: list[dict[str, Any]]
    ) -> CheckResult:
        if permitted is None:
            return CheckResult(
                name=f"{name}_alignment",
                status="not_applicable",
                details=f"Baseline does not specify {name}.",
                category="STANDARDS",
            )
        actual_set = {str(v).lower() for v in actual or []}
        permitted_set = {str(v).lower() for v in permitted}
        extra = sorted(actual_set - permitted_set)
        if extra:
            drifts.append(
                {
                    "field": f"key.{name}",
                    "expected": sorted(permitted_set),
                    "actual": sorted(actual_set),
                }
            )
        return CheckResult(
            name=f"{name}_alignment",
            status="pass" if not extra else "fail",
            details=(
                "Policy permits only curves the baseline allows."
                if not extra
                else f"Policy permits non-baseline curves: {', '.join(extra)}."
            ),
            severity="high",
            category="STANDARDS",
        )

    def _get_nested(self, payload: dict[str, Any], path: str) -> Any:
        current: Any = payload
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
