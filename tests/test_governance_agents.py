from __future__ import annotations

import json
from pathlib import Path

from certguard.agents.bug_triage import BugTriageAgent
from certguard.agents.compliance_assurance import ComplianceAssuranceAgent
from certguard.agents.evidence_vault import EvidenceVaultAgent
from certguard.agents.remediation import RemediationAgent
from certguard.agents.standards_watch import StandardsWatchAgent


def _sample_non_compliant_report() -> dict:
    return {
        "compliant": False,
        "checks": [
            {"name": "validity_days", "status": "pass", "details": "ok"},
            {"name": "signature_algorithm", "status": "fail", "details": "sha1 detected"},
            {"name": "internal_domain_check", "status": "fail", "details": "dev.local"},
        ],
    }


def test_bug_triage_agent_classifies_failures() -> None:
    agent = BugTriageAgent()
    result = agent.run({"report": _sample_non_compliant_report()})
    assert result.success is False
    assert result.data["overall_severity"] == "critical"
    assert result.data["failed_count"] == 2


def test_compliance_assurance_agent_detects_missing_controls() -> None:
    agent = ComplianceAssuranceAgent()
    result = agent.run({"report": _sample_non_compliant_report()})
    assert result.success is False
    failed_assurance = [item for item in result.checks if item.status == "fail"]
    assert len(failed_assurance) >= 1


def test_standards_watch_agent_detects_policy_drift() -> None:
    agent = StandardsWatchAgent()
    policy = {
        "certificate": {"max_validity_days": 500},
        "key": {"minimum_rsa_bits": 2048},
        "signature": {"prohibited_algorithms": ["md5", "sha1"]},
    }
    baseline = {
        "baseline": {"version": "2026.03", "last_reviewed": "2026-03-16"},
        "expected": {
            "certificate": {"max_validity_days": 200},
            "key": {"minimum_rsa_bits": 2048},
            "signature": {"prohibited_algorithms": ["md5", "sha1"]},
        },
    }
    result = agent.run({"policy": policy, "baseline": baseline})
    assert result.success is False
    assert result.data["drift_count"] >= 1


def test_remediation_agent_returns_actions_for_failed_controls() -> None:
    agent = RemediationAgent()
    result = agent.run({"report": _sample_non_compliant_report()})
    assert result.success is False
    assert result.data["failed_count"] == 2
    assert len(result.data["actions"]) == 2


def test_evidence_vault_agent_seals_report(tmp_path: Path) -> None:
    report_path = tmp_path / "compliance_report.json"
    report_path.write_text(json.dumps({"compliant": True}), encoding="utf-8")

    agent = EvidenceVaultAgent()
    result = agent.run({"report_path": str(report_path)})

    assert result.success is True
    seal_path = Path(result.data["seal_path"])
    assert seal_path.exists()
    manifest = json.loads(seal_path.read_text(encoding="utf-8"))
    assert manifest["evidence_file"] == "compliance_report.json"
    assert len(manifest["sha256_fingerprint"]) == 64
