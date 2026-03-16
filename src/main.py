from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from certguard.agents.bug_triage import BugTriageAgent
from certguard.agents.compliance_assurance import ComplianceAssuranceAgent
from certguard.agents.remediation import RemediationAgent
from certguard.agents.standards_watch import StandardsWatchAgent
from certguard.engine import ComplianceGateEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CertGuard compliance gate runner")
    parser.add_argument(
        "--mode",
        choices=["evaluate", "triage", "assure", "watch", "heal"],
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
    raise ValueError(f"Unsupported mode: {args.mode}")


def _run_evaluate(args: argparse.Namespace) -> int:
    if not args.cert:
        raise ValueError("--cert is required in evaluate mode.")
    engine = ComplianceGateEngine(policy_path=Path(args.policy))

    compliant, report = engine.evaluate(
        cert_path=Path(args.cert),
        report_path=Path(args.report),
        evidence_dir=Path(args.evidence_dir),
    )

    print("Certificate:", report.certificate)
    print("Compliant:", "YES" if compliant else "NO")
    for check in report.checks:
        print(f"- {check.name}: {check.status.upper()} ({check.details})")
    print("Lint:", report.lint.get("status"))
    print(f"Report written to {args.report}")
    print(f"Evidence written to {args.evidence_dir}")
    return 0 if compliant else 1


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
    )

    assurance = ComplianceAssuranceAgent().run({"report": healed_report.to_dict()})
    print("Recheck compliant:", "YES" if compliant else "NO")
    print("Assurance:", "YES" if assurance.success else "NO")
    print(f"Healed report written to {args.healed_report}")
    return 0 if (compliant and assurance.success) else 1


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


if __name__ == "__main__":
    raise SystemExit(main())
