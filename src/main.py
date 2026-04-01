from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import yaml

from certguard.agents.bug_triage import BugTriageAgent
from certguard.agents.compliance_assurance import ComplianceAssuranceAgent
from certguard.agents.api_tls_posture import ApiTlsPostureAgent
from certguard.agents.remediation import RemediationAgent
from certguard.agents.reviewer_summary import ReviewerSummaryAgent
from certguard.agents.standards_watch import StandardsWatchAgent
from certguard.agents.trend_snapshot import TrendSnapshotAgent
from certguard.engine import ComplianceGateEngine
from certguard.governance import enforce_protected_context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CertGuard compliance gate runner")
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
        ],
        default="evaluate",
        help="Execution mode",
    )
    parser.add_argument("--cert", help="Path to PEM certificate")
    parser.add_argument(
        "--policy",
        default="policies/cabf_policy.yaml",
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
        choices=["text", "json"],
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
    raise ValueError(f"Unsupported mode: {args.mode}")


def _run_evaluate(args: argparse.Namespace) -> int:
    if not args.cert:
        raise ValueError("--cert is required in evaluate mode.")
    if args.protected_run:
        enforce_protected_context(os.environ)
    engine = ComplianceGateEngine(policy_path=Path(args.policy))

    compliant, report = engine.evaluate(
        cert_path=Path(args.cert),
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
    )
    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("Certificate:", report.certificate)
        print("Compliant:", "YES" if compliant else "NO")
        print(f"Policy Version: {report.policy_version}")
        print(f"Compliance Score: {report.score}%")
        print(f"Risk Level: {report.risk_level}")
        for check in report.checks:
            rule_tag = f"[{check.rule_id}] " if check.rule_id else ""
            print(
                f"- [{check.category}] {rule_tag}{check.name}: {check.status.upper()} "
                f"({check.details})"
            )
            if args.explain:
                if check.rule_id:
                    print(f"  Rule ID: {check.rule_id}")
                print(f"  Why this matters: {check.rationale}")
                print(f"  Standard: {check.standard_reference}")
                print(f"  Recommendation: {check.recommendation}")
        print("Lint:", report.lint.get("status"))
        print(f"Report written to {args.report}")
        print(f"Evidence written to {args.evidence_dir}")
    return _exit_code_from_report(report)


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
    with Path(args.policy).open("r", encoding="utf-8") as stream:
        policy = yaml.safe_load(stream)
    with Path(args.standards_baseline).open("r", encoding="utf-8") as stream:
        baseline = yaml.safe_load(stream)

    agent = StandardsWatchAgent()
    result = agent.run({"policy": policy, "baseline": baseline})
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
    )

    assurance = ComplianceAssuranceAgent().run({"report": healed_report.to_dict()})
    print("Recheck compliant:", "YES" if compliant else "NO")
    print("Assurance:", "YES" if assurance.success else "NO")
    print(f"Healed report written to {args.healed_report}")
    return 0 if (compliant and assurance.success) else 1


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


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _exit_code_from_report(report) -> int:
    failed = [check for check in report.checks if check.status == "fail"]
    if not failed:
        return 0

    severities = {(check.severity or "medium").lower() for check in failed}
    if "critical" in severities:
        return 3
    if "high" in severities or "medium" in severities:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
