from __future__ import annotations

import argparse
import json
import os
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from certguard import __version__, github_output
from certguard.agents.api_tls_posture import ApiTlsPostureAgent
from certguard.agents.bug_triage import BugTriageAgent
from certguard.agents.compliance_assurance import ComplianceAssuranceAgent
from certguard.agents.external_signal_watch import ExternalSignalWatchAgent
from certguard.agents.remediation import RemediationAgent
from certguard.agents.reviewer_summary import ReviewerSummaryAgent
from certguard.agents.standards_watch import StandardsWatchAgent
from certguard.agents.trend_snapshot import TrendSnapshotAgent
from certguard.agents.x509_parser import X509ParserAgent
from certguard.engine import ComplianceGateEngine
from certguard.governance import enforce_protected_context
from certguard.models import SEVERITY_ORDER, ComplianceReport
from certguard.policy import load_policy
from certguard.readiness import (
    assess_readiness,
    load_baseline,
    readiness_exit_code,
    render_readiness_markdown,
    render_readiness_text,
)
from certguard.sarif import to_sarif


def packaged_policy_path() -> str:
    return str(files("certguard.data").joinpath("cabf_policy.yaml"))


def default_policy_path() -> str:
    """Return the repository policy when present, otherwise the packaged copy.

    Auto-detection is a convenience for running inside a checkout, but it means
    the effective policy depends on the working directory. Callers are told
    which file was chosen (see ``_announce_policy_source``) so evidence never
    records a verdict against an unidentified policy.
    """
    repository_policy = Path("policies/cabf_policy.yaml")
    if repository_policy.exists():
        return str(repository_policy)
    return packaged_policy_path()


def _announce_policy_source(args: argparse.Namespace) -> None:
    """Warn when the policy was inferred from the working directory."""
    if getattr(args, "_policy_explicit", False):
        return
    resolved = Path(args.policy)
    if resolved == Path("policies/cabf_policy.yaml"):
        print(
            f"NOTE: using policy auto-detected from the working directory: {resolved}. "
            "Pass --policy explicitly to pin it.",
            file=sys.stderr,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CertGuard compliance gate runner")
    parser.add_argument(
        "--version",
        action="version",
        version=f"certguard {__version__}",
        help="Print the engine version and exit",
    )
    parser.add_argument(
        "--fail-on-waived",
        action="store_true",
        help=(
            "Treat waived findings as failures. Use for audit runs where an "
            "approved exception must still block rather than pass the gate."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=[
            "evaluate",
            "triage",
            "assure",
            "watch",
            "heal",
            "summary",
            "trend",
            "apisec",
            "signals",
            "readiness",
            "export-cps-doc",
            "export-rego",
        ],
        default="evaluate",
        help="Execution mode",
    )
    parser.add_argument("--cert", help="Path to PEM certificate")
    parser.add_argument(
        "--csr",
        help="Path to PEM certificate signing request (pre-issuance; validity/SCT/serial are not assessed)",
    )
    parser.add_argument(
        "--policy",
        default=default_policy_path(),
        help="Path to policy YAML file",
    )
    parser.add_argument(
        "--report",
        default="reports/compliance_report.json",
        help="Path to output compliance report JSON",
    )
    parser.add_argument(
        "--evidence-dir",
        default="audit_evidence",
        help="Directory for policy/lint evidence JSON files",
    )
    parser.add_argument(
        "--report-input",
        default="reports/compliance_report.json",
        help="Path to existing compliance report JSON for triage/assurance",
    )
    parser.add_argument(
        "--standards-baseline",
        default="policies/standards_baseline.yaml",
        help="Path to tracked standards baseline YAML for watch mode",
    )
    parser.add_argument(
        "--watch-output",
        default="reports/standards_watch_report.json",
        help="Path for standards watch output JSON",
    )
    parser.add_argument(
        "--as-of",
        help=(
            "UTC instant for evaluation (YYYY-MM-DD or ISO-8601). Pins expiry "
            "checks in evaluate mode and the dated schedule in watch/readiness. "
            "Same PEM + policy + --as-of yields the same verdict_digest."
        ),
    )
    parser.add_argument(
        "--sarif-output",
        help=(
            "Write SARIF 2.1.0 to this path for GitHub code scanning "
            "(github/codeql-action/upload-sarif)."
        ),
    )
    parser.add_argument(
        "--github-summary",
        action="store_true",
        help="Append a findings table to $GITHUB_STEP_SUMMARY.",
    )
    parser.add_argument(
        "--github-summary-output",
        help="Write the job-summary markdown to this path instead of $GITHUB_STEP_SUMMARY.",
    )
    parser.add_argument(
        "--annotations",
        action="store_true",
        help="Emit GitHub Actions workflow annotations for each finding.",
    )
    parser.add_argument(
        "--readiness-output",
        default="reports/validity_readiness.json",
        help="Path for the validity readiness assessment JSON.",
    )
    parser.add_argument(
        "--require-signed-waivers",
        action="store_true",
        help="Reject unsigned waiver files even if the policy leaves them optional.",
    )
    parser.add_argument(
        "--healed-cert",
        help="Path to corrected certificate for heal mode re-check",
    )
    parser.add_argument(
        "--healed-report",
        default="reports/healed_compliance_report.json",
        help="Output path for healed compliance report JSON",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/compliance_summary.md",
        help="Path for reviewer-friendly markdown summary output",
    )
    parser.add_argument(
        "--protected-run",
        action="store_true",
        help="Require protected GitHub context before execution",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format for evaluation results",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show rationale, standards, and recommendations for each check",
    )
    parser.add_argument("--endpoint", help="API endpoint URL for APISEC mode")
    parser.add_argument(
        "--trend-output",
        default="reports/compliance_trend_snapshot.json",
        help="Path for trend snapshot JSON",
    )
    parser.add_argument(
        "--dcv-attestation",
        help="Path to JSON attestation for domain control validation checks",
    )
    parser.add_argument(
        "--waiver-file",
        help="Path to JSON waiver file for approved false-positive exceptions",
    )
    parser.add_argument(
        "--issuer-cert",
        help="Optional issuer certificate path for RFC 5280 path-linkage checks",
    )
    parser.add_argument(
        "--issuance-attestation",
        help="Path to JSON attestation for issuance controls (HSM/FIPS)",
    )
    parser.add_argument(
        "--external-signals",
        dest="external_signals",
        default="examples/external_signals.json",
        help="Path to JSON file containing curated external standards/security signals",
    )
    parser.add_argument(
        "--signals-output",
        dest="signals_output",
        default="reports/external_signal_snapshot.json",
        help="Path to external signal snapshot output JSON",
    )
    parser.add_argument(
        "--signal-recommendations-output",
        dest="signal_recommendations_output",
        default="reports/external_control_recommendations.json",
        help="Path to external signal recommendation output JSON",
    )
    args = parser.parse_args()
    # Record whether --policy was supplied so auto-detection can be flagged.
    args._policy_explicit = any(
        argument == "--policy" or argument.startswith("--policy=")
        for argument in sys.argv[1:]
    )
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.mode == "evaluate":
            return _run_evaluate(args)
        if args.mode == "triage":
            return _run_triage(args)
        if args.mode == "assure":
            return _run_assure(args)
        if args.mode == "watch":
            return _run_watch(args)
        if args.mode == "heal":
            return _run_heal(args)
        if args.mode == "summary":
            return _run_summary(args)
        if args.mode == "trend":
            return _run_trend(args)
        if args.mode == "apisec":
            return _run_apisec(args)
        if args.mode == "signals":
            return _run_signals(args)
        if args.mode == "readiness":
            return _run_readiness(args)
        if args.mode == "export-cps-doc":
            return _run_export_cps_doc(args)
        if args.mode == "export-rego":
            return _run_export_rego(args)
        raise ValueError(f"Unsupported mode: {args.mode}")
    except (FileNotFoundError, PermissionError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _run_evaluate(args: argparse.Namespace) -> int:
    if args.cert and args.csr:
        raise ValueError("evaluate accepts exactly one of --cert or --csr, not both.")
    target = args.cert or args.csr
    if not target:
        raise ValueError("evaluate requires --cert or --csr.")
    if args.protected_run:
        enforce_protected_context(os.environ)
    _announce_policy_source(args)
    engine = ComplianceGateEngine(policy_path=Path(args.policy))

    compliant, report = engine.evaluate(
        cert_path=Path(target),
        report_path=Path(args.report),
        evidence_dir=Path(args.evidence_dir),
        dcv_attestation=_read_json(Path(args.dcv_attestation))
        if args.dcv_attestation
        else None,
        issuance_attestation=_read_json(Path(args.issuance_attestation))
        if args.issuance_attestation
        else None,
        issuer_cert_path=Path(args.issuer_cert) if args.issuer_cert else None,
        waiver_path=Path(args.waiver_file) if args.waiver_file else None,
        require_signed_waivers=args.require_signed_waivers or None,
        evaluated_at=args.as_of,
        input_kind="csr" if args.csr else None,
    )
    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.output == "sarif":
        print(json.dumps(to_sarif(report, policy_path=args.policy), indent=2))
    else:
        _print_report(report, compliant=compliant, explain=args.explain)
        print(f"Report written to {args.report}")
        print(f"Evidence written to {args.evidence_dir}")
    if args.sarif_output:
        sarif_path = Path(args.sarif_output)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(
            json.dumps(to_sarif(report, policy_path=args.policy), indent=2),
            encoding="utf-8",
        )
        if args.output != "sarif":
            print(f"SARIF written to {sarif_path}")
    if args.github_summary or args.github_summary_output:
        github_output.write_job_summary(
            report,
            policy_path=args.policy,
            summary_path=args.github_summary_output,
        )
    if args.annotations:
        github_output.emit_annotations(report, sys.stdout)
    return _exit_code_from_report(report, fail_on_waived=args.fail_on_waived)


# Human-readable result labels; "PASS" is not a credential.
STATUS_LABELS = {
    "pass": "PASS",  # nosec B105
    "fail": "FAIL",
    "waived": "WAIVED",
    "not_applicable": "N/A",
}


def _print_report(
    report: ComplianceReport, *, compliant: bool, explain: bool
) -> None:
    """Render a verdict without a single percentage.

    A percentage was removed in report schema 2.0: controls disabled by policy
    counted toward it, so an almost-empty profile read 100%, and a critical
    failure could still present as ~95%. Findings by severity plus an explicit
    coverage line say what actually happened.
    """
    print("Certificate:" if report.input_kind != "csr" else "CSR:", report.certificate)
    print("Input:", report.input_kind)
    print("Compliant:", "YES" if compliant else "NO")
    print(f"Risk Level: {report.risk_level}")
    print(f"Engine Version: {report.engine_version}")
    print(f"Policy Version: {report.policy_version}")
    if report.evaluated_at:
        print(f"Evaluated at: {report.evaluated_at}")
    if report.verdict_digest:
        print(f"Verdict digest: {report.verdict_digest}")

    findings = ", ".join(
        f"{severity}={report.findings.get(severity, 0)}"
        for severity in SEVERITY_ORDER
        if report.findings.get(severity)
    )
    print(f"Control findings: {findings or 'none'}")
    coverage = report.coverage
    print(
        f"Coverage: {coverage['controls_evaluated']} of "
        f"{coverage['controls_defined']} controls evaluated "
        f"({coverage['passed']} pass, {coverage['failed']} fail, "
        f"{coverage['waived']} waived, {coverage['not_applicable']} not applicable)"
    )
    print("Lint:", report.lint.get("status"))
    print("")

    for check in report.checks:
        rule_tag = f"[{check.rule_id}] " if check.rule_id else ""
        label = STATUS_LABELS.get(check.status, check.status.upper())
        print(
            f"- [{check.category}] {rule_tag}{check.name}: {label} ({check.details})"
        )
        if explain:
            if check.rule_id:
                print(f"  Rule ID: {check.rule_id}")
            print(f"  Severity: {check.normalized_severity()}")
            print(f"  Why this matters: {check.rationale}")
            print(f"  Standard: {check.standard_reference}")
            print(f"  Recommendation: {check.recommendation}")


def _run_triage(args: argparse.Namespace) -> int:
    report = _read_json(Path(args.report_input))
    agent = BugTriageAgent()
    result = agent.run({"report": report})
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print("Overall severity:", result.data.get("overall_severity"))
    print("Next action:", result.data.get("next_action"))
    for finding in result.data.get("findings", []):
        print(
            f"- {finding['check']}: {finding['severity'].upper()} - {finding['recommendation']}"
        )
    return 0 if result.success else 1


def _run_assure(args: argparse.Namespace) -> int:
    report = _read_json(Path(args.report_input))
    agent = ComplianceAssuranceAgent()
    result = agent.run({"report": report})
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    for check in result.checks:
        print(f"- {check.name}: {check.status.upper()} ({check.details})")
    return 0 if result.success else 1


def _run_watch(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy))
    baseline = _read_yaml(Path(args.standards_baseline))
    if not isinstance(policy, dict):
        raise ValueError(f"--policy must contain a YAML object: {args.policy}")
    if not isinstance(baseline, dict):
        raise ValueError(
            f"--standards-baseline must contain a YAML object: {args.standards_baseline}"
        )

    agent = StandardsWatchAgent()
    result = agent.run(
        {"policy": policy, "baseline": baseline, "as_of": args.as_of}
    )
    output_path = Path(args.watch_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "agent": result.agent,
                "success": result.success,
                "checks": [check.to_dict() for check in result.checks],
                "summary": result.data,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print("Drifts:", result.data.get("drift_count"))
    print(f"Report written to {output_path}")
    return 0 if result.success else 1


def _run_heal(args: argparse.Namespace) -> int:
    if args.protected_run:
        enforce_protected_context(os.environ)
    report = _read_json(Path(args.report_input))
    remediation = RemediationAgent().run({"report": report})

    print("Agent:", remediation.agent)
    print("Success:", "YES" if remediation.success else "NO")
    print("Remediation actions:", remediation.data.get("failed_count"))
    for action in remediation.data.get("actions", []):
        print(
            f"- {action['check']}: {action['action_type'].upper()} - {action['step']} "
            f"(owner={action['owner']})"
        )

    if not args.healed_cert:
        print("No --healed-cert provided. Remediation plan generated only.")
        return 1 if remediation.data.get("failed_count", 0) > 0 else 0

    engine = ComplianceGateEngine(policy_path=Path(args.policy))
    compliant, healed_report = engine.evaluate(
        cert_path=Path(args.healed_cert),
        report_path=Path(args.healed_report),
        evidence_dir=Path(args.evidence_dir),
        dcv_attestation=_read_json(Path(args.dcv_attestation))
        if args.dcv_attestation
        else None,
        issuance_attestation=_read_json(Path(args.issuance_attestation))
        if args.issuance_attestation
        else None,
        issuer_cert_path=Path(args.issuer_cert) if args.issuer_cert else None,
        waiver_path=Path(args.waiver_file) if args.waiver_file else None,
        require_signed_waivers=args.require_signed_waivers or None,
    )

    assurance = ComplianceAssuranceAgent().run({"report": healed_report.to_dict()})
    print("Recheck compliant:", "YES" if compliant else "NO")
    print("Assurance:", "YES" if assurance.success else "NO")
    print(f"Healed report written to {args.healed_report}")
    return 0 if (compliant and assurance.success) else 1


def _run_readiness(args: argparse.Namespace) -> int:
    """Assess a policy (and optionally one certificate) against the schedule."""
    _announce_policy_source(args)
    policy = load_policy(Path(args.policy))
    baseline = load_baseline(Path(args.standards_baseline))

    parser_data = None
    if args.cert:
        parser_result = X509ParserAgent().run({"cert_path": args.cert})
        if not parser_result.success:
            raise ValueError("; ".join(parser_result.errors))
        parser_data = parser_result.data

    assessment = assess_readiness(
        policy, baseline, as_of=args.as_of, parser_data=parser_data
    )

    output_path = Path(args.readiness_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(assessment, indent=2), encoding="utf-8")

    if args.output == "json":
        print(json.dumps(assessment, indent=2))
    else:
        print(render_readiness_text(assessment))
        print(f"\nAssessment written to {output_path}")

    if args.github_summary or args.github_summary_output:
        target = args.github_summary_output or os.getenv("GITHUB_STEP_SUMMARY")
        if target:
            summary_path = Path(target)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with summary_path.open("a", encoding="utf-8") as handle:
                handle.write(render_readiness_markdown(assessment) + "\n")

    return readiness_exit_code(assessment)


def _run_summary(args: argparse.Namespace) -> int:
    report = _read_json(Path(args.report_input))
    result = ReviewerSummaryAgent().run(
        {"report": report, "output_path": args.summary_output}
    )
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print(f"Summary written to {result.data.get('summary_path')}")
    return 0 if result.success else 1


def _run_trend(args: argparse.Namespace) -> int:
    report = _read_json(Path(args.report_input))
    result = TrendSnapshotAgent().run(
        {
            "report": report,
            "output_path": args.trend_output,
            "run_id": os.getenv("GITHUB_RUN_ID", "local-run"),
            "trigger": os.getenv("GITHUB_EVENT_NAME", "manual"),
        }
    )
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print(f"Trend snapshot written to {result.data.get('snapshot_path')}")
    return 0 if result.success else 1


def _run_apisec(args: argparse.Namespace) -> int:
    if not args.endpoint:
        raise ValueError("--endpoint is required in apisec mode.")
    result = ApiTlsPostureAgent().run({"endpoint": args.endpoint})
    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print(f"Endpoint: {result.data.get('endpoint')}")
    print(f"TLS Version: {result.data.get('tls_version')}")
    print(f"Cipher Suite: {result.data.get('cipher_suite')}")
    print(f"Risk Level: {result.data.get('risk_level')}")
    for check in result.checks:
        print(f"- {check.name}: {check.status.upper()} ({check.details})")
    return 0 if result.success else 2


def _run_signals(args: argparse.Namespace) -> int:
    signals = _read_json(Path(args.external_signals))
    if not isinstance(signals, list):
        raise ValueError("--external-signals must point to a JSON array of signal objects.")

    result = ExternalSignalWatchAgent().run({"signals": signals})
    snapshot_path = Path(args.signals_output)
    rec_path = Path(args.signal_recommendations_output)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    rec_path.parent.mkdir(parents=True, exist_ok=True)

    snapshot_payload = {
        "agent": result.agent,
        "success": result.success,
        "generated_at": result.data.get("generated_at"),
        "signal_count": result.data.get("signal_count"),
        "high_priority_signals": result.data.get("high_priority_signals"),
        "signals": result.data.get("signals", []),
    }
    rec_payload = {
        "agent": result.agent,
        "success": result.success,
        "recommendation_count": result.data.get("recommendation_count"),
        "recommendations": result.data.get("recommendations", []),
    }
    snapshot_path.write_text(json.dumps(snapshot_payload, indent=2), encoding="utf-8")
    rec_path.write_text(json.dumps(rec_payload, indent=2), encoding="utf-8")

    print("Agent:", result.agent)
    print("Success:", "YES" if result.success else "NO")
    print(f"Signals: {result.data.get('signal_count')}")
    print(f"Recommendations: {result.data.get('recommendation_count')}")
    print(f"Snapshot written to {snapshot_path}")
    print(f"Recommendations written to {rec_path}")
    return 0 if result.success else 1


def _run_export_cps_doc(args: argparse.Namespace) -> int:
    from certguard.policy_exporter import export_policy_to_markdown

    out_path = args.summary_output or "reports/compliance_summary.md"
    export_policy_to_markdown(args.policy, out_path)
    print("Single Source of Truth Policy-as-Code Exporter")
    print(f"Policy: {args.policy}")
    print(f"CP/CPS Section 7 Documentation exported to: {out_path}")
    return 0


def _run_export_rego(args: argparse.Namespace) -> int:
    from certguard.rego import export_policy_to_rego

    out_path = args.summary_output or "policies/rego/validity.rego"
    export_policy_to_rego(args.policy, out_path)
    print("Generated OPA/Rego from the YAML policy")
    print(f"Policy: {args.policy}")
    print(f"Rego written to: {out_path}")
    return 0


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"JSON file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc.msg} (line {exc.lineno})") from exc


def _read_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"YAML file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc


def _exit_code_from_report(report, fail_on_waived: bool = False) -> int:
    """Map a report onto the documented exit codes.

    0 no failing checks, 1 low-severity only, 2 medium/high or lint failure,
    3 at least one critical failure. With ``fail_on_waived`` a waived finding is
    counted as if it had failed, so an approved exception still blocks an audit
    run rather than silently passing the gate.
    """
    blocking_statuses = {"fail", "waived"} if fail_on_waived else {"fail"}
    failed = [check for check in report.checks if check.status in blocking_statuses]
    lint_failed = report.lint.get("status") == "fail"
    if not failed:
        return 2 if lint_failed else 0

    severities = {(check.severity or "medium").lower() for check in failed}
    if "critical" in severities:
        return 3
    if "high" in severities or "medium" in severities:
        return 2
    return 2 if lint_failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
