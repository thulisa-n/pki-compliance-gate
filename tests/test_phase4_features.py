from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import certguard.engine as engine_module
from certguard.agents.policy_validator import PolicyValidatorAgent
from certguard.engine import ComplianceGateEngine


def _base_policy() -> dict:
    return yaml.safe_load(Path("policies/cabf_policy.yaml").read_text(encoding="utf-8"))


def test_dcv_required_fails_without_attestation(tmp_path: Path) -> None:
    policy = _base_policy()
    policy["dcv"]["required"] = True
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"
    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=report_path,
        evidence_dir=evidence_dir,
    )

    assert compliant is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    dcv_method = next(item for item in report["checks"] if item["name"] == "dcv_method")
    assert dcv_method["status"] == "fail"


def test_waiver_can_suppress_known_false_positive(tmp_path: Path) -> None:
    policy_path = Path("policies/cabf_policy.yaml")
    waiver_path = tmp_path / "waivers.json"
    waiver_path.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "check": "signature_algorithm",
                        "reason": "Planned migration exception",
                        "ticket": "PKI-999",
                        "expires_on": "2026-12-31",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"
    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(
        cert_path=Path("tests/certificates/sha1_cert.pem"),
        report_path=report_path,
        evidence_dir=evidence_dir,
        waiver_path=waiver_path,
    )

    assert compliant is True
    report = json.loads(report_path.read_text(encoding="utf-8"))
    signature = next(item for item in report["checks"] if item["name"] == "signature_algorithm")
    assert signature["status"] == "waived"
    waiver_evidence = json.loads(
        (evidence_dir / "waiver_results.json").read_text(encoding="utf-8")
    )
    assert waiver_evidence["status"] == "applied"


def test_waiver_without_expiry_or_ticket_is_not_applied(tmp_path: Path) -> None:
    policy_path = Path("policies/cabf_policy.yaml")
    waiver_path = tmp_path / "waivers.json"
    waiver_path.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "check": "signature_algorithm",
                        "reason": "Missing required governance fields",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"
    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(
        cert_path=Path("tests/certificates/sha1_cert.pem"),
        report_path=report_path,
        evidence_dir=evidence_dir,
        waiver_path=waiver_path,
    )

    assert compliant is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    signature = next(item for item in report["checks"] if item["name"] == "signature_algorithm")
    assert signature["status"] == "fail"


def test_opa_enabled_with_missing_policy_file_fails_closed(tmp_path: Path) -> None:
    policy = _base_policy()
    policy["opa"]["enabled"] = True
    policy["opa"]["policy_file"] = str(tmp_path / "missing.rego")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"
    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=report_path,
        evidence_dir=evidence_dir,
    )

    assert compliant is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    opa_check = next(item for item in report["checks"] if item["name"] == "opa_policy_gate")
    assert opa_check["status"] == "fail"


def test_opa_enabled_with_missing_binary_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _base_policy()
    policy["opa"]["enabled"] = True
    policy["opa"]["policy_file"] = str(Path("policies/rego/validity.rego"))
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")

    def _raise_missing_binary(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(engine_module.subprocess, "run", _raise_missing_binary)

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"
    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=report_path,
        evidence_dir=evidence_dir,
    )

    assert compliant is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    opa_check = next(item for item in report["checks"] if item["name"] == "opa_policy_gate")
    assert opa_check["status"] == "fail"


def test_rfc5280_extension_profile_checks_detect_edge_cases() -> None:
    policy = _base_policy()
    policy["rfc5280"]["require_subject_key_identifier"] = True
    policy["rfc5280"]["require_authority_key_identifier"] = True
    policy["rfc5280"]["allowed_critical_extensions"] = ["2.5.29.15", "2.5.29.19"]

    parser_data = {
        "validity_days": 90,
        "san_dns": ["example.com"],
        "is_rsa": True,
        "rsa_key_size": 2048,
        "signature_algorithm": "sha256",
        "basic_constraints_ca": False,
        "key_usage": ["digital_signature", "key_encipherment"],
        "has_subject_key_identifier": False,
        "has_authority_key_identifier": True,
        "critical_extension_oids": ["2.5.29.15", "1.2.3.4"],
    }
    result = PolicyValidatorAgent().run({"policy": policy, "parser_data": parser_data})

    ski_check = next(check for check in result.checks if check.name == "rfc5280_subject_key_identifier")
    critical_check = next(
        check for check in result.checks if check.name == "rfc5280_critical_extension_profile"
    )
    assert ski_check.status == "fail"
    assert critical_check.status == "fail"
    assert "1.2.3.4" in critical_check.details


def test_rfc5280_path_linkage_checks_require_issuer_data() -> None:
    policy = _base_policy()
    policy["rfc5280"]["require_path_issuer_subject_match"] = True
    policy["rfc5280"]["require_path_aki_ski_match"] = True

    parser_data = {
        "validity_days": 90,
        "san_dns": ["example.com"],
        "is_rsa": True,
        "rsa_key_size": 2048,
        "signature_algorithm": "sha256",
        "basic_constraints_ca": False,
        "key_usage": ["digital_signature", "key_encipherment"],
        "has_subject_key_identifier": True,
        "has_authority_key_identifier": True,
        "subject_key_identifier": "aaaa",
        "authority_key_identifier": "bbbb",
        "critical_extension_oids": [],
        "issuer": "CN=Issuer",
    }
    result = PolicyValidatorAgent().run({"policy": policy, "parser_data": parser_data})
    issuer_subject = next(
        check for check in result.checks if check.name == "rfc5280_path_issuer_subject_match"
    )
    aki_ski = next(check for check in result.checks if check.name == "rfc5280_path_aki_ski_match")
    assert issuer_subject.status == "fail"
    assert aki_ski.status == "fail"


def test_issuance_controls_fail_without_attestation_when_required() -> None:
    policy = _base_policy()
    policy["issuance"]["require_hsm_attestation"] = True
    policy["issuance"]["min_fips_level"] = 3

    parser_data = {
        "validity_days": 90,
        "san_dns": ["example.com"],
        "is_rsa": True,
        "rsa_key_size": 2048,
        "signature_algorithm": "sha256",
        "basic_constraints_ca": False,
        "key_usage": ["digital_signature", "key_encipherment"],
        "critical_extension_oids": [],
    }
    result = PolicyValidatorAgent().run({"policy": policy, "parser_data": parser_data})
    hsm = next(check for check in result.checks if check.name == "issuance_hsm_attestation")
    fips = next(check for check in result.checks if check.name == "issuance_fips_level")
    assert hsm.status == "fail"
    assert fips.status == "fail"


def test_crypto_transition_checks_fail_when_transition_targets_not_met() -> None:
    policy = _base_policy()
    policy["crypto_transition"]["enabled"] = True
    policy["crypto_transition"]["target_max_validity_days"] = 90
    policy["crypto_transition"]["target_min_rsa_bits"] = 3072
    policy["crypto_transition"]["approved_signature_algorithms"] = ["sha384", "sha512"]

    parser_data = {
        "validity_days": 120,
        "san_dns": ["example.com"],
        "is_rsa": True,
        "rsa_key_size": 2048,
        "signature_algorithm": "sha256",
        "basic_constraints_ca": False,
        "key_usage": ["digital_signature", "key_encipherment"],
        "critical_extension_oids": [],
    }
    result = PolicyValidatorAgent().run({"policy": policy, "parser_data": parser_data})
    validity = next(
        check for check in result.checks if check.name == "crypto_transition_validity_target"
    )
    rsa_target = next(
        check for check in result.checks if check.name == "crypto_transition_rsa_target"
    )
    hash_target = next(
        check for check in result.checks if check.name == "crypto_transition_signature_hash"
    )
    assert validity.status == "fail"
    assert rsa_target.status == "fail"
    assert hash_target.status == "fail"


def test_crypto_transition_checks_pass_when_targets_met() -> None:
    policy = _base_policy()
    policy["crypto_transition"]["enabled"] = True
    policy["crypto_transition"]["target_max_validity_days"] = 90
    policy["crypto_transition"]["target_min_rsa_bits"] = 3072
    policy["crypto_transition"]["approved_signature_algorithms"] = ["sha256", "sha384", "sha512"]

    parser_data = {
        "validity_days": 90,
        "san_dns": ["example.com"],
        "is_rsa": True,
        "rsa_key_size": 4096,
        "signature_algorithm": "sha384",
        "basic_constraints_ca": False,
        "key_usage": ["digital_signature", "key_encipherment"],
        "critical_extension_oids": [],
    }
    result = PolicyValidatorAgent().run({"policy": policy, "parser_data": parser_data})
    validity = next(
        check for check in result.checks if check.name == "crypto_transition_validity_target"
    )
    rsa_target = next(
        check for check in result.checks if check.name == "crypto_transition_rsa_target"
    )
    hash_target = next(
        check for check in result.checks if check.name == "crypto_transition_signature_hash"
    )
    assert validity.status == "pass"
    assert rsa_target.status == "pass"
    assert hash_target.status == "pass"
