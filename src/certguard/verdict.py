"""Canonical verdict digest: same inputs must hash the same."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from certguard.models import ComplianceReport


def canonical_verdict(report: ComplianceReport) -> dict[str, Any]:
    """The subset of a report that is the *decision*, not the file path.

    Absolute certificate paths and wall-clock ``generated_at`` are omitted so
    two machines evaluating the same PEM, policy, and ``--as-of`` instant
    produce the same digest.
    """
    return {
        "report_schema_version": report.report_schema_version,
        "engine_version": report.engine_version,
        "policy_version": report.policy_version,
        "evaluated_at": report.parser_data.get("evaluated_at"),
        "input_kind": report.parser_data.get("input_kind", "certificate"),
        "compliant": report.compliant,
        "risk_level": report.risk_level,
        "findings": report.findings,
        "coverage": report.coverage,
        "checks": [
            {
                "actual_value": check.actual_value,
                "details": check.details,
                "name": check.name,
                "rule_id": check.rule_id,
                "severity": check.normalized_severity(),
                "status": check.status,
            }
            for check in sorted(report.checks, key=lambda item: item.name)
        ],
    }


def verdict_digest(report: ComplianceReport) -> str:
    payload = json.dumps(
        canonical_verdict(report),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
