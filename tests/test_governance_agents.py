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


def test_compliance_assurance_agent_detects_flag_mismatch() -> None:
    agent = ComplianceAssuranceAgent()
    forged_report = {
        "compliant": True,
        "checks": [
            {"name": "validity_days", "status": "pass", "details": "ok"},
            {"name": "san_extension", "status": "pass", "details": "ok"},
            {"name": "rsa_key_size", "status": "pass", "details": "ok"},
            {"name": "signature_algorithm", "status": "fail", "details": "sha1 detected"},
            {"name": "internal_domain_check", "status": "pass", "details": "ok"},
        ],
    }
    result = agent.run({"report": forged_report})
    assert result.success is False
    flag_check = next(item for item in result.checks if item.name == "assure_final_compliance_flag")
    assert flag_check.status == "fail"
    assert "mismatch" in flag_check.details


def test_compliance_assurance_agent_rejects_duplicate_check_names() -> None:
    agent = ComplianceAssuranceAgent()
    report = {
        "compliant": True,
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "validity_days", "status": "fail"},
        ],
    }
    result = agent.run({"report": report})
    assert result.success is False
    assert result.errors
    assert "malformed or duplicate checks" in result.errors[0]


def test_compliance_assurance_agent_rejects_non_boolean_compliant_flag() -> None:
    agent = ComplianceAssuranceAgent()
    report = {
        "compliant": "true",
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "san_extension", "status": "pass"},
            {"name": "rsa_key_size", "status": "pass"},
            {"name": "signature_algorithm", "status": "pass"},
            {"name": "internal_domain_check", "status": "pass"},
        ],
    }
    result = agent.run({"report": report})
    assert result.success is False
    assert result.errors
    assert "must be a boolean value" in result.errors[0]


def test_standards_watch_agent_detects_policy_drift() -> None:
    agent = StandardsWatchAgent()
    policy = {
        "certificate": {"max_validity_days": 500},
        "key": {"minimum_rsa_bits": 2048, "minimum_ec_bits": 256},
        "signature": {"prohibited_algorithms": ["md5", "sha1"]},
        "dcv": {"max_age_days": 30},
    }
    baseline = {
        "baseline": {"version": "2026.03", "last_reviewed": "2026-03-16"},
        "schedule": [
            {
                "effective": "2026-03-15",
                "max_validity_days": 200,
                "dcv_reuse_days": 200,
            }
        ],
        "expected": {
            "certificate": {"max_validity_days": 200},
            "key": {"minimum_rsa_bits": 2048, "minimum_ec_bits": 256},
            "signature": {"prohibited_algorithms": ["md5", "sha1"]},
        },
    }
    result = agent.run(
        {"policy": policy, "baseline": baseline, "as_of": "2026-09-11"}
    )
    assert result.success is False
    assert result.data["drift_count"] >= 1
    drift_fields = {item["field"] for item in result.data["drifts"]}
    assert "max_validity_days" in drift_fields


def test_compliance_assurance_reports_not_applicable_controls() -> None:
    """A control the policy did not enable is neither a pass nor a failure."""
    agent = ComplianceAssuranceAgent()
    report = {
        "compliant": True,
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "san_extension", "status": "pass"},
            {"name": "rsa_key_size", "status": "pass"},
            {"name": "signature_algorithm", "status": "pass"},
            {"name": "internal_domain_check", "status": "not_applicable"},
        ],
    }
    result = agent.run({"report": report})

    assert result.success is True
    check = next(
        item for item in result.checks if item.name == "assure_internal_domain_check"
    )
    assert check.status == "not_applicable"
    assert result.data["controls_not_applicable"] == 1


def test_compliance_assurance_reports_waived_controls() -> None:
    agent = ComplianceAssuranceAgent()
    report = {
        "compliant": True,
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "san_extension", "status": "pass"},
            {"name": "rsa_key_size", "status": "waived"},
            {"name": "signature_algorithm", "status": "pass"},
            {"name": "internal_domain_check", "status": "pass"},
        ],
    }
    result = agent.run({"report": report})

    check = next(item for item in result.checks if item.name == "assure_rsa_key_size")
    assert check.status == "waived"
    assert "approved waiver" in check.details


def test_bug_triage_uses_severity_from_the_report() -> None:
    """Triage must not disagree with the verdict it is triaging.

    The local severity table said validity_days was medium while the engine
    said high; the report is now the authority.
    """
    agent = BugTriageAgent()
    report = {
        "compliant": False,
        "checks": [
            {
                "name": "validity_days",
                "status": "fail",
                "details": "too long",
                "severity": "high",
                "recommendation": "Shorten the validity period.",
            }
        ],
    }
    result = agent.run({"report": report})

    finding = result.data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["recommendation"] == "Shorten the validity period."


def test_remediation_agent_returns_actions_for_failed_controls() -> None:
    agent = RemediationAgent()
    result = agent.run({"report": _sample_non_compliant_report()})
    assert result.success is False
    assert result.data["failed_count"] == 2
    assert len(result.data["actions"]) == 2


def test_evidence_vault_agent_records_report_digest(tmp_path: Path) -> None:
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
    # A digest is not a signature and the artefact must not imply otherwise.
    assert manifest["integrity_note"] == "SHA-256 digest, not a signature."
    assert "digest_recorded_at" in manifest
