from __future__ import annotations

import argparse
from pathlib import Path

from certguard.engine import ComplianceGateEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CertGuard compliance gate runner")
    parser.add_argument("--cert", required=True, help="Path to PEM certificate")
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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


if __name__ == "__main__":
    raise SystemExit(main())
