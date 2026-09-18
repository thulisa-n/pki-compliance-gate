from __future__ import annotations

from pathlib import Path

from certguard.agents.policy_validator import CSR_APPLICABLE_CONTROLS
from certguard.engine import ComplianceGateEngine
from tests.support.certificates import CertSpec, write_csr

POLICY_PATH = Path("policies/cabf_policy.yaml")


def test_weak_csr_fails_before_issuance(tmp_path: Path) -> None:
    csr = write_csr(tmp_path / "weak.csr", CertSpec(key="rsa1024"))
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    report, _ = engine.assess(cert_path=csr, input_kind="csr", evaluated_at="2026-09-18")
    assert report.input_kind == "csr"
    assert report.compliant is False
    rsa = next(check for check in report.checks if check.name == "rsa_key_size")
    assert rsa.status == "fail"
    validity = next(check for check in report.checks if check.name == "validity_days")
    assert validity.status == "not_applicable"


def test_csr_does_not_claim_issued_certificate_controls(tmp_path: Path) -> None:
    csr = write_csr(tmp_path / "ok.csr", CertSpec())
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    report, _ = engine.assess(cert_path=csr, input_kind="csr", evaluated_at="2026-09-18")
    for check in report.checks:
        if check.name in CSR_APPLICABLE_CONTROLS:
            continue
        assert check.status == "not_applicable", check.name
