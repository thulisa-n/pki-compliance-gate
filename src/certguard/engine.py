from __future__ import annotations

import json
import os
# Controlled use for zlint CLI integration.
import subprocess  # nosec B404
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from certguard.agents.evidence_vault import EvidenceVaultAgent
from certguard.agents.policy_validator import PolicyValidatorAgent
from certguard.agents.x509_parser import X509ParserAgent
from certguard.models import CheckResult, ComplianceReport
from certguard.policy import load_policy


class ComplianceGateEngine:
    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self.policy = load_policy(self.policy_path)
        self.parser_agent = X509ParserAgent()
        self.policy_agent = PolicyValidatorAgent()
        self.evidence_vault_agent = EvidenceVaultAgent()

    def evaluate(
        self,
        cert_path: Path,
        report_path: Path,
        evidence_dir: Path,
        dcv_attestation: dict[str, Any] | None = None,
        issuance_attestation: dict[str, Any] | None = None,
        issuer_cert_path: Path | None = None,
        waiver_path: Path | None = None,
    ) -> tuple[bool, ComplianceReport]:
        parser_result = self.parser_agent.run({"cert_path": str(cert_path)})
        if not parser_result.success:
            raise ValueError("; ".join(parser_result.errors))

        issuer_parser_data: dict[str, Any] | None = None
        if issuer_cert_path is not None:
            issuer_result = self.parser_agent.run({"cert_path": str(issuer_cert_path)})
            if not issuer_result.success:
                raise ValueError("; ".join(issuer_result.errors))
            issuer_parser_data = issuer_result.data

        policy_result = self.policy_agent.run(
            {
                "policy": self.policy,
                "parser_data": parser_result.data,
                "dcv_attestation": dcv_attestation,
                "issuer_parser_data": issuer_parser_data,
                "issuance_attestation": issuance_attestation,
            }
        )
        opa_result = self._run_opa_if_enabled(parser_result.data)
        policy_checks = list(policy_result.checks)
        if opa_result["check"] is not None:
            policy_checks.append(opa_result["check"])

        waiver_result = self._apply_waivers(policy_checks, waiver_path)
        policy_checks = waiver_result["checks"]
        policy_failures = [check for check in policy_checks if check.status == "fail"]

        lint_result = self._run_lint_controls(cert_path)
        lint_fail = lint_result.get("status") == "fail"

        compliant = (not policy_failures) and (not lint_fail)
        report = ComplianceReport.new(
            certificate=str(cert_path),
            compliant=compliant,
            checks=policy_checks,
            parser_data=parser_result.data,
            lint=lint_result,
            policy_version=self.policy.get("metadata", {}).get("version", "unknown"),
        )

        report_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

        (evidence_dir / "policy_checks.json").write_text(
            json.dumps([c.to_dict() for c in policy_checks], indent=2),
            encoding="utf-8",
        )
        (evidence_dir / "lint_results.json").write_text(
            json.dumps(lint_result, indent=2), encoding="utf-8"
        )
        (evidence_dir / "waiver_results.json").write_text(
            json.dumps(waiver_result["summary"], indent=2), encoding="utf-8"
        )
        (evidence_dir / "opa_results.json").write_text(
            json.dumps(opa_result["summary"], indent=2), encoding="utf-8"
        )
        seal_result = self.evidence_vault_agent.run({"report_path": str(report_path)})
        if not seal_result.success:
            raise ValueError("; ".join(seal_result.errors))
        self._write_evidence_manifest(
            evidence_dir=evidence_dir,
            report_path=report_path,
            seal_path=Path(seal_result.data["seal_path"]),
        )

        return compliant, report

    def _write_evidence_manifest(
        self, evidence_dir: Path, report_path: Path, seal_path: Path
    ) -> None:
        manifest_path = evidence_dir / "evidence_manifest.json"
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": os.getenv("GITHUB_RUN_ID", "local-run"),
            "workflow": os.getenv("GITHUB_WORKFLOW", "local-dev"),
            "actor": os.getenv("GITHUB_ACTOR", "manual-run"),
            "report_file": str(report_path),
            "seal_file": str(seal_path),
            "evidence_files": [
                str(evidence_dir / "policy_checks.json"),
                str(evidence_dir / "lint_results.json"),
                str(evidence_dir / "waiver_results.json"),
                str(evidence_dir / "opa_results.json"),
            ],
        }
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _run_opa_if_enabled(self, parser_data: dict[str, Any]) -> dict[str, Any]:
        opa_cfg = self.policy.get("opa", {})
        if not opa_cfg.get("enabled", False):
            return {
                "check": None,
                "summary": {
                    "status": "skipped",
                    "details": "OPA policy evaluation disabled in policy.",
                },
            }

        policy_file = Path(str(opa_cfg.get("policy_file", "")))
        if not policy_file.exists():
            check = CheckResult(
                name="opa_policy_gate",
                status="fail",
                details=f"OPA policy file not found: {policy_file}",
                rule_id="OPA-POLICY",
                category="POLICY",
                severity="high",
                standard_reference="OPA/Rego policy-as-code",
            )
            return {"check": check, "summary": {"status": "fail", "details": check.details}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump(parser_data, handle)
            input_path = Path(handle.name)

        cmd = [
            "opa",
            "eval",
            "--format",
            "raw",
            "--data",
            str(policy_file),
            "--input",
            str(input_path),
            "data.pki.compliance.allow",
        ]

        try:
            process = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, check=False
            )
        except FileNotFoundError:
            input_path.unlink(missing_ok=True)
            return {
                "check": CheckResult(
                    name="opa_policy_gate",
                    status="fail",
                    details="OPA binary not installed while opa.enabled=true.",
                    rule_id="OPA-POLICY",
                    category="POLICY",
                    severity="high",
                    standard_reference="OPA/Rego policy-as-code",
                ),
                "summary": {
                    "status": "fail",
                    "details": "OPA binary not installed while policy requires OPA.",
                    "policy_file": str(policy_file),
                },
            }

        input_path.unlink(missing_ok=True)
        output = (process.stdout or "").strip().lower()
        allowed = process.returncode == 0 and output == "true"
        status = "pass" if allowed else "fail"
        details = (
            f"OPA evaluation result: {output or 'unknown'}"
            if process.returncode == 0
            else f"OPA evaluation command failed with code {process.returncode}"
        )
        return {
            "check": CheckResult(
                name="opa_policy_gate",
                status=status,
                details=details,
                rule_id="OPA-POLICY",
                category="POLICY",
                severity="high",
                standard_reference="OPA/Rego policy-as-code",
            ),
            "summary": {
                "status": status,
                "details": details,
                "policy_file": str(policy_file),
                "stdout": (process.stdout or "").strip(),
                "stderr": (process.stderr or "").strip(),
            },
        }

    def _apply_waivers(
        self, checks: list[CheckResult], waiver_path: Path | None
    ) -> dict[str, Any]:
        if waiver_path is None:
            return {
                "checks": checks,
                "summary": {"status": "skipped", "details": "No waiver file provided.", "applied": []},
            }
        if not waiver_path.exists():
            return {
                "checks": checks,
                "summary": {
                    "status": "ignored",
                    "details": f"Waiver file not found: {waiver_path}",
                    "applied": [],
                },
            }

        payload = json.loads(waiver_path.read_text(encoding="utf-8"))
        waivers = payload.get("waivers", []) if isinstance(payload, dict) else []
        now = datetime.now(timezone.utc).date()
        applied: list[dict[str, Any]] = []

        for check in checks:
            if check.status != "fail":
                continue
            for waiver in waivers:
                if not isinstance(waiver, dict):
                    continue
                if waiver.get("check") != check.name:
                    continue
                ticket = waiver.get("ticket")
                if not isinstance(ticket, str) or not ticket.strip():
                    continue
                expires_on = waiver.get("expires_on")
                if not isinstance(expires_on, str):
                    continue
                try:
                    expiry = datetime.fromisoformat(expires_on).date()
                except ValueError:
                    continue
                if expiry < now:
                    continue
                check.status = "waived"
                reason = waiver.get("reason", "No reason provided")
                check.details = f"{check.details} Waived: {reason} (ticket: {ticket})."
                applied.append(
                    {
                        "check": check.name,
                        "reason": reason,
                        "ticket": ticket,
                        "expires_on": expires_on,
                    }
                )
                break

        return {
            "checks": checks,
            "summary": {
                "status": "applied" if applied else "none",
                "details": f"Applied {len(applied)} waiver(s).",
                "source": str(waiver_path),
                "applied": applied,
            },
        }

    def _run_lint_controls(self, cert_path: Path) -> dict[str, Any]:
        zlint_result = self._run_zlint_if_enabled(cert_path)
        asn1_result = self._run_asn1parse_if_enabled(cert_path)
        controls = {"zlint": zlint_result, "asn1parse": asn1_result}
        failing = [
            name for name, payload in controls.items() if payload.get("status") == "fail"
        ]
        if failing:
            status = "fail"
            details = f"Lint controls failed: {', '.join(failing)}"
        elif any(payload.get("status") == "pass" for payload in controls.values()):
            status = "pass"
            details = "Lint controls passed."
        else:
            status = "skipped"
            details = "All lint controls skipped."
        return {"status": status, "details": details, "controls": controls}

    def _run_zlint_if_enabled(self, cert_path: Path) -> dict[str, Any]:
        lint_cfg = self.policy.get("lint", {})
        if not lint_cfg.get("enable_zlint", False):
            return {"status": "skipped", "details": "zlint disabled in policy"}

        # Safe invocation: fixed binary and argument structure, shell disabled.
        cmd = ["zlint", "-pretty", str(cert_path)]
        try:
            process = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, check=False
            )
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

    def _run_asn1parse_if_enabled(self, cert_path: Path) -> dict[str, Any]:
        lint_cfg = self.policy.get("lint", {})
        if not lint_cfg.get("enable_asn1parse", False):
            return {"status": "skipped", "details": "asn1parse disabled in policy"}

        cmd = ["openssl", "asn1parse", "-in", str(cert_path), "-inform", "PEM"]
        try:
            process = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, check=False
            )
        except FileNotFoundError:
            return {"status": "skipped", "details": "openssl not installed"}

        fail_on_error = lint_cfg.get("fail_on_asn1_error", True)
        failed = process.returncode != 0 and fail_on_error
        return {
            "tool": "openssl asn1parse",
            "status": "fail" if failed else "pass",
            "return_code": process.returncode,
            "details": "ASN.1 parsing completed." if process.returncode == 0 else "ASN.1 parsing returned non-zero exit.",
            "raw_output": ((process.stdout or "") + ("\n" + process.stderr if process.stderr else "")).strip(),
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
