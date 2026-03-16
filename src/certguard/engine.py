from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

from certguard.agents.policy_validator import PolicyValidatorAgent
from certguard.agents.x509_parser import X509ParserAgent
from certguard.models import ComplianceReport


class ComplianceGateEngine:
    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self.policy = self._load_policy()
        self.parser_agent = X509ParserAgent()
        self.policy_agent = PolicyValidatorAgent()

    def evaluate(
        self,
        cert_path: Path,
        report_path: Path,
        evidence_dir: Path,
    ) -> tuple[bool, ComplianceReport]:
        parser_result = self.parser_agent.run({"cert_path": str(cert_path)})
        if not parser_result.success:
            raise ValueError("; ".join(parser_result.errors))

        policy_result = self.policy_agent.run(
            {
                "policy": self.policy,
                "parser_data": parser_result.data,
            }
        )

        lint_result = self._run_zlint_if_enabled(cert_path)
        lint_fail = lint_result.get("status") == "fail"

        compliant = policy_result.success and (not lint_fail)
        report = ComplianceReport.new(
            certificate=str(cert_path),
            compliant=compliant,
            checks=policy_result.checks,
            parser_data=parser_result.data,
            lint=lint_result,
        )

        report_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

        (evidence_dir / "policy_checks.json").write_text(
            json.dumps([c.to_dict() for c in policy_result.checks], indent=2),
            encoding="utf-8",
        )
        (evidence_dir / "lint_results.json").write_text(
            json.dumps(lint_result, indent=2), encoding="utf-8"
        )

        return compliant, report

    def _load_policy(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")
        with self.policy_path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream)

    def _run_zlint_if_enabled(self, cert_path: Path) -> dict[str, Any]:
        lint_cfg = self.policy.get("lint", {})
        if not lint_cfg.get("enable_zlint", False):
            return {"status": "skipped", "details": "zlint disabled in policy"}

        cmd = ["zlint", str(cert_path)]
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return {"status": "skipped", "details": "zlint not installed"}

        combined_output = (process.stdout or "") + ("\n" + process.stderr if process.stderr else "")
        status = "pass" if process.returncode == 0 else "fail"
        return {
            "status": status,
            "return_code": process.returncode,
            "details": combined_output.strip(),
        }
