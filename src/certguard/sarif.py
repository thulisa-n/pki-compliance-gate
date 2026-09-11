"""Render a compliance report as SARIF 2.1.0.

SARIF is what makes the gate fit how teams already triage: GitHub ingests it
into the repository's Security tab with per-finding severity, rule
documentation and file annotations, rather than leaving the result as an exit
code buried in a log.

The mapping is deliberately conservative:

* Only ``fail`` and ``waived`` controls become results. A ``pass`` is not a
  finding, and a ``not_applicable`` control was never assessed -- emitting
  either would repeat the dishonesty report schema 2.0 exists to fix.
* Waived findings are emitted at ``note`` level with the waiver recorded in the
  message, so an approved exception stays visible in the Security tab instead
  of disappearing. A waiver suppresses the gate, not the record.
* Every control in ``CHECK_METADATA`` is declared as a rule, including ones
  that did not fire, so rule documentation is complete and stable between runs.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from certguard import __version__
from certguard.agents.policy_validator import CHECK_METADATA
from certguard.models import ComplianceReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/thulisa-n/pki-compliance-gate"

#: CertGuard severity -> SARIF level.
_LEVEL_BY_SEVERITY: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "warning",
}

#: CertGuard severity -> GitHub code scanning `security-severity`, which drives
#: the ordering and the "Critical/High/Medium/Low" label in the Security tab.
_SECURITY_SEVERITY: dict[str, str] = {
    "critical": "9.3",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.1",
    "unknown": "5.0",
}


def to_sarif(
    report: ComplianceReport,
    *,
    policy_path: str | Path | None = None,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Convert a compliance report into a SARIF log."""
    rule_names = sorted(CHECK_METADATA)
    rule_index = {name: index for index, name in enumerate(rule_names)}
    rules = [_rule(name) for name in rule_names]

    artifact_uri = _relative_uri(report.certificate, repo_root)
    results: list[dict[str, Any]] = []

    for check in report.checks:
        if check.status not in {"fail", "waived"}:
            continue
        severity = check.normalized_severity()
        level = _LEVEL_BY_SEVERITY.get(severity, "warning")
        message = check.details
        if check.status == "waived":
            # Keep the finding visible but non-blocking, and say why.
            level = "note"
            message = f"[WAIVED] {message}"
        if check.recommendation:
            message = f"{message} Recommendation: {check.recommendation}"

        entry: dict[str, Any] = {
            "ruleId": check.name,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        # A certificate has no meaningful line; anchoring at
                        # line 1 is what GitHub needs to render an annotation.
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
            "partialFingerprints": {
                "certguardControl/v1": _fingerprint(check.name, report.certificate)
            },
            "properties": {
                "status": check.status,
                "severity": severity,
                "category": check.category,
                "standardReference": check.standard_reference,
                "policyValue": check.policy_value,
                "actualValue": check.actual_value,
            },
        }
        if check.name in rule_index:
            entry["ruleIndex"] = rule_index[check.name]
        results.append(entry)

    invocation: dict[str, Any] = {
        "executionSuccessful": report.compliant,
        "exitCodeDescription": (
            "0 compliant; 1 low-severity only; 2 medium/high or lint failure; "
            "3 critical failure"
        ),
    }
    if policy_path is not None:
        invocation["properties"] = {"policy": str(policy_path)}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CertGuard",
                        "fullName": "CertGuard Engine (PKI Compliance Gate)",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "engineVersion": report.engine_version,
                    "reportSchemaVersion": report.report_schema_version,
                    "policyVersion": report.policy_version,
                    "riskLevel": report.risk_level,
                    "findings": report.findings,
                    # Coverage travels with the SARIF log so a reader can see
                    # how much was assessed, not just what failed.
                    "coverage": report.coverage,
                },
            }
        ],
    }


def _rule(name: str) -> dict[str, Any]:
    meta = CHECK_METADATA.get(name, {})
    severity = (meta.get("severity") or "unknown").lower()
    tags = ["security", "pki"]
    category = meta.get("category")
    if category:
        tags.append(category.lower())
    reference = meta.get("standard_reference")
    if reference:
        tags.append("external/standard")

    return {
        "id": name,
        "name": _pascal_case(name),
        "shortDescription": {"text": _short_description(name, meta)},
        "fullDescription": {
            "text": meta.get("rationale") or f"CertGuard control {name}."
        },
        "help": {
            "text": meta.get("recommendation") or "See the CertGuard coverage matrix.",
            "markdown": _help_markdown(name, meta),
        },
        "defaultConfiguration": {
            "level": _LEVEL_BY_SEVERITY.get(severity, "warning")
        },
        "properties": {
            "tags": tags,
            "problem.severity": _LEVEL_BY_SEVERITY.get(severity, "warning"),
            "security-severity": _SECURITY_SEVERITY.get(severity, "5.0"),
            "certguardSeverity": severity,
            "ruleId": meta.get("rule_id"),
            "standardReference": reference,
        },
    }


def _short_description(name: str, meta: dict[str, str]) -> str:
    rule_id = meta.get("rule_id")
    label = name.replace("_", " ")
    return f"{label} ({rule_id})" if rule_id else label


def _help_markdown(name: str, meta: dict[str, str]) -> str:
    lines = [f"### `{name}`", ""]
    if meta.get("rule_id"):
        lines.append(f"**Rule:** {meta['rule_id']}")
    if meta.get("standard_reference"):
        lines.append(f"**Standard:** {meta['standard_reference']}")
    if meta.get("severity"):
        lines.append(f"**Severity:** {meta['severity']}")
    lines.append("")
    if meta.get("rationale"):
        lines += ["**Why this matters**", "", meta["rationale"], ""]
    if meta.get("recommendation"):
        lines += ["**How to fix**", "", meta["recommendation"], ""]
    lines.append(
        "A control reported as `not_applicable` was defined but not enabled by "
        "the active policy profile. It was not assessed and is never counted "
        "as a pass."
    )
    return "\n".join(lines)


def _pascal_case(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_") if part)


def _relative_uri(certificate: str, repo_root: str | Path | None) -> str:
    """Express the certificate path relative to the repository root.

    GitHub matches SARIF locations against tracked files, so an absolute
    container path would produce an unattached annotation.
    """
    root = Path(
        repo_root or os.getenv("GITHUB_WORKSPACE") or Path.cwd()
    ).resolve()
    candidate = Path(certificate)
    try:
        resolved = candidate.resolve()
    except OSError:
        return candidate.as_posix()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        # Outside the workspace (a temp file, say). Fall back to the basename
        # rather than leaking an absolute path into published SARIF.
        return candidate.name


def _fingerprint(check_name: str, certificate: str) -> str:
    basis = f"{check_name}|{Path(certificate).name}".encode()
    return hashlib.sha256(basis).hexdigest()[:32]
