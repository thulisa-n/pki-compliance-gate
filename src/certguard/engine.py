from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

from certguard.agents.policy_validator import PolicyValidatorAgent
from certguard.agents.x509_parser import X509ParserAgent
from certguard.models import ComplianceReport
from certguard.policy import load_policy


class ComplianceGateEngine:
    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self.policy = load_policy(self.policy_path)
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

    def _run_zlint_if_enabled(self, cert_path: Path) -> dict[str, Any]:
        lint_cfg = self.policy.get("lint", {})
        if not lint_cfg.get("enable_zlint", False):
            return {"status": "skipped", "details": "zlint disabled in policy"}

        cmd = ["zlint", "-pretty", str(cert_path)]
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return {"status": "skipped", "details": "zlint not installed"}

        fail_severities = {
            self._normalize_severity(value)
            for value in lint_cfg.get("fail_severities", ["error", "fatal"])
        }
        fail_on_error = lint_cfg.get("fail_on_error", True)
        parsed = self._parse_zlint_output(process.stdout or "")

        if parsed["entries"]:
            matched = [
                entry for entry in parsed["entries"] if entry["severity"] in fail_severities
            ]
            status = "fail" if matched else "pass"
            details = f"zlint parsed {len(parsed['entries'])} checks"
        else:
            status = "fail" if (process.returncode != 0 and fail_on_error) else "pass"
            details = "zlint output not parseable; fallback to process exit code"

        combined_output = (process.stdout or "") + (
            "\n" + process.stderr if process.stderr else ""
        )
        return {
            "tool": "zlint",
            "status": status,
            "return_code": process.returncode,
            "details": details,
            "summary": {
                "fail_severities": sorted(fail_severities),
                "counts": parsed["counts"],
                "matched_failures": [entry["lint"] for entry in matched] if parsed["entries"] else [],
            },
            "raw_output": combined_output.strip(),
        }

    def _parse_zlint_output(self, output: str) -> dict[str, Any]:
        if not output.strip():
            return {"entries": [], "counts": {}}

        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return {"entries": [], "counts": {}}

        entries: list[dict[str, str]] = []
        blocks = payload.get("results") if isinstance(payload, dict) else None
        candidates = blocks if isinstance(blocks, dict) else payload
        if not isinstance(candidates, dict):
            return {"entries": [], "counts": {}}

        for lint_name, lint_data in candidates.items():
            if not isinstance(lint_data, dict):
                continue
            result = lint_data.get("result")
            if not isinstance(result, str):
                continue
            severity = self._normalize_severity(result)
            entries.append({"lint": lint_name, "severity": severity})

        counts = dict(Counter(entry["severity"] for entry in entries))
        return {"entries": entries, "counts": counts}

    def _normalize_severity(self, value: str) -> str:
        normalized = value.strip().lower()
        aliases = {
            "warning": "warn",
            "not applicable": "na",
        }
        return aliases.get(normalized, normalized)
