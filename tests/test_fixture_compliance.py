"""Engine-level compliance assertions for every prebuilt certificate fixture.

Each test validates the expected pass/fail outcome directly through
ComplianceGateEngine, complementing the CI fixture-matrix job with
in-repo pytest coverage.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")
FIXTURES_DIR = Path("tests/certificates")


def _evaluate_fixture(fixture_name: str, tmp_path: Path) -> dict:
    cert_path = FIXTURES_DIR / fixture_name
    report_path = tmp_path / "report.json"
    evidence_dir = tmp_path / "evidence"
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    compliant, _ = engine.evaluate(cert_path, report_path, evidence_dir)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["_compliant_result"] = compliant
    return report


def test_valid_cert_is_compliant(tmp_path: Path) -> None:
    report = _evaluate_fixture("valid_cert.pem", tmp_path)
    assert report["_compliant_result"] is True
    assert report["compliant"] is True
    assert report["score"] == 100.0
    assert report["risk_level"] == "LOW"


def test_sha1_cert_fails_signature_algorithm(tmp_path: Path) -> None:
    report = _evaluate_fixture("sha1_cert.pem", tmp_path)
    assert report["_compliant_result"] is False
    sig_check = next(c for c in report["checks"] if c["name"] == "signature_algorithm")
    assert sig_check["status"] == "fail"
    assert sig_check["severity"] == "critical"
    assert report["risk_level"] == "HIGH"


def test_long_validity_cert_fails_max_days(tmp_path: Path) -> None:
    report = _evaluate_fixture("long_validity_cert.pem", tmp_path)
    assert report["_compliant_result"] is False
    validity_check = next(c for c in report["checks"] if c["name"] == "validity_days")
    assert validity_check["status"] == "fail"


def test_no_san_cert_fails_san_requirement(tmp_path: Path) -> None:
    report = _evaluate_fixture("no_san_cert.pem", tmp_path)
    assert report["_compliant_result"] is False
    san_check = next(c for c in report["checks"] if c["name"] == "san_extension")
    assert san_check["status"] == "fail"


def test_internal_domain_cert_fails_domain_check(tmp_path: Path) -> None:
    report = _evaluate_fixture("internal_domain_cert.pem", tmp_path)
    assert report["_compliant_result"] is False
    domain_check = next(c for c in report["checks"] if c["name"] == "internal_domain_check")
    assert domain_check["status"] == "fail"


def test_weak_key_cert_fails_rsa_key_size(tmp_path: Path) -> None:
    report = _evaluate_fixture("weak_key_cert.pem", tmp_path)
    assert report["_compliant_result"] is False
    key_check = next(c for c in report["checks"] if c["name"] == "rsa_key_size")
    assert key_check["status"] == "fail"
    assert key_check["severity"] == "critical"
