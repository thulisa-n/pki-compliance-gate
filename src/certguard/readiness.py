"""Readiness against the dated CA/Browser Forum validity schedule.

Ballot SC-081v3 reduces the maximum subscriber certificate validity to 100 days
on 2027-03-15 and 47 days on 2029-03-15, with domain validation reuse falling
to 10 days. Every organisation with public TLS certificates has to re-verify
its posture three times in three years.

This answers, for one policy profile and optionally one certificate: which
phases are already satisfied, which are not, what specifically has to change,
and how long there is to do it.

It is deliberately part of the open-source core. A team should be able to find
out whether they have a 2027 problem without paying anyone.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

READY = "ready"
ACTION_NEEDED = "action_needed"
UNKNOWN = "unknown"


def load_baseline(baseline_path: str | Path) -> dict[str, Any]:
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Standards baseline not found: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Standards baseline must be a YAML object: {path}")
    return payload


def assess_readiness(
    policy: dict[str, Any],
    baseline: dict[str, Any],
    *,
    as_of: date | str | None = None,
    parser_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess a policy (and optionally one certificate) against every phase."""
    today = _resolve_date(as_of)
    schedule = _parse_schedule(baseline.get("schedule"))
    if not schedule:
        return {
            "as_of": today.isoformat(),
            "baseline_version": _nested(baseline, "baseline.version"),
            "baseline_authority": _nested(baseline, "baseline.authority"),
            "phases": [],
            "required_changes": [],
            "overall_status": UNKNOWN,
            "detail": (
                "The standards baseline contains no dated schedule. Add "
                "entries under `schedule:` in policies/standards_baseline.yaml."
            ),
        }

    policy_max_validity = _nested(policy, "certificate.max_validity_days")
    policy_dcv_reuse = _nested(policy, "dcv.max_age_days")
    cert_validity = (
        parser_data.get("validity_days") if isinstance(parser_data, dict) else None
    )

    phases: list[dict[str, Any]] = []
    required_changes: list[dict[str, Any]] = []
    active_index = _active_index(schedule, today)

    for index, phase in enumerate(schedule):
        if index < active_index:
            # A superseded phase is history, not a target.
            continue
        position = (
            "in_force"
            if index == active_index
            else ("next" if index == active_index + 1 else "future")
        )
        gaps: list[dict[str, Any]] = []

        _add_gap(
            gaps,
            field="certificate.max_validity_days",
            current=policy_max_validity,
            required=phase["max_validity_days"],
            phase=phase,
            today=today,
        )
        _add_gap(
            gaps,
            field="dcv.max_age_days",
            current=policy_dcv_reuse,
            required=phase["dcv_reuse_days"],
            phase=phase,
            today=today,
        )
        if isinstance(cert_validity, int):
            _add_gap(
                gaps,
                field="certificate.validity_days (evaluated certificate)",
                current=cert_validity,
                required=phase["max_validity_days"],
                phase=phase,
                today=today,
            )

        status = READY if not gaps else ACTION_NEEDED
        phases.append(
            {
                "position": position,
                "effective": phase["effective"].isoformat(),
                "days_until_effective": max((phase["effective"] - today).days, 0),
                "max_validity_days": phase["max_validity_days"],
                "dcv_reuse_days": phase["dcv_reuse_days"],
                "status": status,
                "gaps": gaps,
                "note": phase.get("note"),
            }
        )
        required_changes.extend(gaps)

    overall = READY if all(p["status"] == READY for p in phases) else ACTION_NEEDED
    return {
        "as_of": today.isoformat(),
        "baseline_version": _nested(baseline, "baseline.version"),
        "baseline_authority": _nested(baseline, "baseline.authority"),
        "policy_version": _nested(policy, "metadata.version"),
        "certificate_validity_days": cert_validity,
        "phases": phases,
        "required_changes": required_changes,
        "overall_status": overall,
        "detail": (
            "Policy satisfies every tracked phase."
            if overall == READY
            else f"{len(required_changes)} change(s) required across "
            f"{len([p for p in phases if p['status'] == ACTION_NEEDED])} phase(s)."
        ),
    }


def render_readiness_text(assessment: dict[str, Any]) -> str:
    """Human-readable table for the terminal and the job summary."""
    lines = [
        "CertGuard validity readiness",
        f"  Evaluated at : {assessment['as_of']}",
        f"  Authority    : {assessment.get('baseline_authority') or 'unknown'}"
        f" (baseline {assessment.get('baseline_version') or 'unknown'})",
        f"  Policy       : v{assessment.get('policy_version') or 'unknown'}",
    ]
    if assessment.get("certificate_validity_days") is not None:
        lines.append(
            f"  Certificate  : {assessment['certificate_validity_days']} day validity"
        )
    lines += ["", f"  Overall      : {assessment['overall_status'].upper()}", ""]

    if not assessment["phases"]:
        lines.append(f"  {assessment['detail']}")
        return "\n".join(lines)

    lines.append(
        "  Phase      Effective     Max validity  DCV reuse  In        Status"
    )
    lines.append(
        "  ---------  ------------  ------------  ---------  --------  ------------"
    )
    for phase in assessment["phases"]:
        lines.append(
            f"  {phase['position']:<9}  {phase['effective']:<12}  "
            f"{phase['max_validity_days']:>12}  {phase['dcv_reuse_days']:>9}  "
            f"{phase['days_until_effective']:>6}d  "
            f"{'READY' if phase['status'] == READY else 'ACTION NEEDED'}"
        )

    if assessment["required_changes"]:
        lines += ["", "  Required changes:"]
        seen: set[tuple[str, int, str]] = set()
        for gap in assessment["required_changes"]:
            key = (gap["field"], gap["required"], gap["effective"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"    - {gap['field']}: {gap['current']} -> {gap['required']} "
                f"by {gap['effective']} ({gap['days_remaining']} days)"
            )
    return "\n".join(lines)


def render_readiness_markdown(assessment: dict[str, Any]) -> str:
    lines = [
        "## CertGuard validity readiness",
        "",
        f"**Overall:** {assessment['overall_status'].replace('_', ' ').upper()}"
        f" &nbsp;&nbsp; **As at:** {assessment['as_of']}",
        "",
        f"Authority: {assessment.get('baseline_authority') or 'unknown'}",
        "",
        "| Phase | Effective | Max validity | DCV reuse | In | Status |",
        "| :--- | :--- | ---: | ---: | ---: | :--- |",
    ]
    for phase in assessment["phases"]:
        status = "READY" if phase["status"] == READY else "ACTION NEEDED"
        lines.append(
            f"| {phase['position']} | {phase['effective']} "
            f"| {phase['max_validity_days']} | {phase['dcv_reuse_days']} "
            f"| {phase['days_until_effective']}d | {status} |"
        )
    if assessment["required_changes"]:
        lines += ["", "### Required changes", ""]
        seen: set[tuple[str, int, str]] = set()
        for gap in assessment["required_changes"]:
            key = (gap["field"], gap["required"], gap["effective"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"- `{gap['field']}`: **{gap['current']} → {gap['required']}** "
                f"by {gap['effective']} ({gap['days_remaining']} days)"
            )
    return "\n".join(lines)


def readiness_exit_code(assessment: dict[str, Any]) -> int:
    """0 ready, 1 a future phase needs work, 2 the phase in force is breached.

    A breach of the phase already in force is a present-tense compliance
    problem, so it exits 2 like any medium/high finding. A gap against a future
    phase is a plan, not a failure, so it exits 1.
    """
    if assessment["overall_status"] == UNKNOWN:
        return 2
    for phase in assessment["phases"]:
        if phase["position"] == "in_force" and phase["status"] == ACTION_NEEDED:
            return 2
    return 0 if assessment["overall_status"] == READY else 1


def _add_gap(
    gaps: list[dict[str, Any]],
    *,
    field: str,
    current: Any,
    required: int,
    phase: dict[str, Any],
    today: date,
) -> None:
    if not isinstance(current, int):
        return
    if current <= required:
        return
    gaps.append(
        {
            "field": field,
            "current": current,
            "required": required,
            "effective": phase["effective"].isoformat(),
            "days_remaining": max((phase["effective"] - today).days, 0),
        }
    )


def _active_index(schedule: list[dict[str, Any]], today: date) -> int:
    index = 0
    for position, phase in enumerate(schedule):
        if phase["effective"] <= today:
            index = position
    return index


def _parse_schedule(raw: Any) -> list[dict[str, Any]]:
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


def _resolve_date(value: date | str | None) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str) and value.strip():
        return datetime.fromisoformat(value.strip()).date()
    return datetime.now(timezone.utc).date()


def _nested(payload: dict[str, Any], dotted: str) -> Any:
    current: Any = payload
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
