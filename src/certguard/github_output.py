"""GitHub Actions surfaces: job summary and workflow annotations.

A gate that only sets an exit code makes the reader open the log and read
argparse output. These two surfaces put the verdict where people already look:
a rendered table in the run summary, and annotations on the run itself.

Both are plain text protocols, so there is no dependency and nothing to
configure beyond the environment variables Actions already sets.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TextIO

from certguard.models import SEVERITY_ORDER, ComplianceReport

#: CertGuard severity -> Actions annotation command.
_ANNOTATION_COMMAND: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
    "unknown": "warning",
}

# Human-readable result labels; "PASS" is not a credential.
_STATUS_ICON: dict[str, str] = {
    "pass": "PASS",  # nosec B105
    "fail": "FAIL",
    "waived": "WAIVED",
    "not_applicable": "n/a",
}


def is_github_actions(env: dict[str, str] | None = None) -> bool:
    environ = env if env is not None else dict(os.environ)
    return environ.get("GITHUB_ACTIONS") == "true"


def render_job_summary(
    report: ComplianceReport, *, policy_path: str | Path | None = None
) -> str:
    """Markdown for `$GITHUB_STEP_SUMMARY`."""
    verdict = "COMPLIANT" if report.compliant else "NON-COMPLIANT"
    findings = ", ".join(
        f"{severity} {report.findings.get(severity, 0)}"
        for severity in SEVERITY_ORDER
        if report.findings.get(severity)
    )
    coverage = report.coverage

    lines = [
        "## CertGuard compliance gate",
        "",
        f"**Result:** {verdict} &nbsp;&nbsp; **Risk:** {report.risk_level}",
        "",
        "| | |",
        "| :--- | :--- |",
        f"| Certificate | `{Path(report.certificate).name}` |",
        f"| Findings | {findings or 'none'} |",
        f"| Coverage | {coverage['controls_evaluated']} of "
        f"{coverage['controls_defined']} controls evaluated "
        f"({coverage['not_applicable']} not applicable) |",
        f"| Lint | {report.lint.get('status', 'unknown')} |",
        f"| Policy | `{policy_path or 'unknown'}` (v{report.policy_version}) |",
        f"| Engine | {report.engine_version} |",
        "",
    ]

    blocking = [c for c in report.checks if c.status in {"fail", "waived"}]
    if blocking:
        lines += [
            "### Findings",
            "",
            "| Control | Severity | Status | Standard | Detail |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        ordered = sorted(
            blocking,
            key=lambda c: (
                SEVERITY_ORDER.index(c.normalized_severity()),
                c.name,
            ),
        )
        for check in ordered:
            lines.append(
                f"| `{check.name}` | {check.normalized_severity()} "
                f"| {_STATUS_ICON.get(check.status, check.status)} "
                f"| {check.standard_reference or ''} "
                f"| {_escape_cell(check.details)} |"
            )
        lines.append("")
    else:
        lines += ["No failing controls.", ""]

    not_applicable = [c for c in report.checks if c.status == "not_applicable"]
    if not_applicable:
        lines += [
            "<details><summary>"
            f"{len(not_applicable)} control(s) defined but not enabled by this "
            "policy (not assessed, never counted as a pass)"
            "</summary>",
            "",
        ]
        for check in sorted(not_applicable, key=lambda c: c.name):
            lines.append(f"- `{check.name}` — {_escape_cell(check.details)}")
        lines += ["", "</details>", ""]

    return "\n".join(lines)


def write_job_summary(
    report: ComplianceReport,
    *,
    policy_path: str | Path | None = None,
    summary_path: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> Path | None:
    """Append the job summary to `$GITHUB_STEP_SUMMARY`.

    Returns the path written, or None when not running under Actions and no
    explicit path was given.
    """
    environ = env if env is not None else dict(os.environ)
    target = summary_path or environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return None
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(render_job_summary(report, policy_path=policy_path) + "\n")
    return path


def annotation_lines(report: ComplianceReport) -> list[str]:
    """Workflow commands for each failing or waived control.

    Certificates have no source line to anchor to, so these are emitted without
    a file location: Actions renders them against the run, which is the correct
    place for a policy verdict about an artefact.
    """
    lines: list[str] = []
    ordered = sorted(
        (c for c in report.checks if c.status in {"fail", "waived"}),
        key=lambda c: (SEVERITY_ORDER.index(c.normalized_severity()), c.name),
    )
    for check in ordered:
        severity = check.normalized_severity()
        command = _ANNOTATION_COMMAND.get(severity, "warning")
        if check.status == "waived":
            command = "notice"
        title = f"CertGuard {severity}: {check.name}"
        if check.rule_id:
            title = f"CertGuard {severity}: {check.name} ({check.rule_id})"
        message = check.details
        if check.status == "waived":
            message = f"[WAIVED] {message}"
        if check.recommendation:
            message = f"{message} Recommendation: {check.recommendation}"
        lines.append(f"::{command} title={_escape_prop(title)}::{_escape_data(message)}")

    if not ordered:
        coverage = report.coverage
        lines.append(
            "::notice title=CertGuard::"
            + _escape_data(
                f"No failing controls. {coverage['controls_evaluated']} of "
                f"{coverage['controls_defined']} controls evaluated, "
                f"{coverage['not_applicable']} not applicable."
            )
        )
    return lines


def emit_annotations(report: ComplianceReport, stream: TextIO) -> int:
    lines = annotation_lines(report)
    for line in lines:
        print(line, file=stream)
    return len(lines)


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def _escape_data(value: str) -> str:
    # Workflow command data escaping, per the Actions toolkit.
    return (
        value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    )


def _escape_prop(value: str) -> str:
    return (
        _escape_data(value).replace(":", "%3A").replace(",", "%2C")
    )
