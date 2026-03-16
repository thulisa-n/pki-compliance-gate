from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certguard.engine import ComplianceGateEngine


def _write_self_signed_cert(
    cert_path: Path,
    *,
    common_name: str,
    san_dns: list[str],
    days: int,
    rsa_bits: int = 2048,
    hash_algo: hashes.HashAlgorithm = hashes.SHA256(),
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    now = datetime.now(timezone.utc)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in san_dns]),
            critical=False,
        )
    )

    cert = cert_builder.sign(private_key=key, algorithm=hash_algo)
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))


def _write_policy(policy_path: Path) -> None:
    policy = {
        "metadata": {
            "standard": "CA/Browser Forum Baseline Requirements",
            "version": "2026-MVP",
            "terms": "test policy",
        },
        "terms": [],
        "certificate": {"max_validity_days": 398, "require_san": True},
        "key": {"minimum_rsa_bits": 2048},
        "signature": {"prohibited_algorithms": ["sha1", "md5"]},
        "domains": {
            "forbid_internal_names": True,
            "blocked_suffixes": [".local", ".internal", ".intranet"],
        },
        "lint": {
            "enable_zlint": False,
            "fail_on_error": True,
            "fail_severities": ["error", "fatal"],
        },
    }
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


def test_compliant_certificate_passes(tmp_path: Path) -> None:
    cert_path = tmp_path / "valid.pem"
    _write_self_signed_cert(
        cert_path,
        common_name="example.com",
        san_dns=["example.com", "www.example.com"],
        days=90,
    )

    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"

    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(cert_path, report_path, evidence_dir)

    assert compliant is True
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["compliant"] is True
    assert len(report["checks"]) >= 5
    assert report_path.with_suffix(".json.seal").exists()


def test_internal_domain_fails_policy(tmp_path: Path) -> None:
    cert_path = tmp_path / "invalid_internal.pem"
    _write_self_signed_cert(
        cert_path,
        common_name="dev.local",
        san_dns=["dev.local"],
        days=30,
    )

    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)

    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"

    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(cert_path, report_path, evidence_dir)

    assert compliant is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    internal_check = next(item for item in report["checks"] if item["name"] == "internal_domain_check")
    assert internal_check["status"] == "fail"


def test_signature_algorithm_allows_sha256_fixture(tmp_path: Path) -> None:
    cert_path = Path("tests/certificates/valid_cert.pem")
    policy_path = Path("policies/cabf_policy.yaml")
    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"

    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(cert_path, report_path, evidence_dir)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    signature_check = next(item for item in report["checks"] if item["name"] == "signature_algorithm")
    assert signature_check["status"] == "pass"
    assert compliant is True


def test_signature_algorithm_blocks_sha1_fixture(tmp_path: Path) -> None:
    cert_path = Path("tests/certificates/sha1_cert.pem")
    policy_path = Path("policies/cabf_policy.yaml")
    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "audit_evidence"

    engine = ComplianceGateEngine(policy_path=policy_path)
    compliant, _ = engine.evaluate(cert_path, report_path, evidence_dir)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    signature_check = next(item for item in report["checks"] if item["name"] == "signature_algorithm")
    assert signature_check["status"] == "fail"
    assert "sha1" in signature_check["details"]
    assert compliant is False
