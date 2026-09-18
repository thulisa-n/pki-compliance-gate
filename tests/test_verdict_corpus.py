"""Published corpus: committed PEMs/CSRs match expected exit codes and failures."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import yaml
from cryptography import x509

from certguard.cli import _exit_code_from_report
from certguard.engine import ComplianceGateEngine

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "corpus" / "verdicts.yaml"


def _as_of(pem_path: Path, kind: str, evaluate: str):
    if kind == "csr":
        return "2026-09-18T00:00:00+00:00"
    cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
    if evaluate == "inside_window":
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        return cert.not_valid_before_utc + (delta / 2)
    if evaluate == "after_not_after":
        return cert.not_valid_after_utc + timedelta(seconds=1)
    raise ValueError(f"Unknown evaluate strategy: {evaluate}")


def test_every_corpus_case_matches_expected_verdict() -> None:
    spec = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    engine = ComplianceGateEngine(policy_path=REPO_ROOT / spec["policy"])
    for case in spec["cases"]:
        pem_path = REPO_ROOT / case["pem"]
        kind = case.get("kind", "certificate")
        report, _ = engine.assess(
            cert_path=pem_path,
            evaluated_at=_as_of(pem_path, kind, case["evaluate"]),
            input_kind="csr" if kind == "csr" else "certificate",
        )
        exit_code = _exit_code_from_report(report)
        failed = {check.name for check in report.checks if check.status == "fail"}
        assert exit_code == case["exit_code"], (
            f"{case['id']}: exit {exit_code} != {case['exit_code']}; failed={sorted(failed)}"
        )
        assert report.compliant is case["compliant"], case["id"]
        missing = set(case["must_fail"]) - failed
        assert not missing, f"{case['id']}: missing failures {sorted(missing)}"


def test_pinned_as_of_is_reproducible() -> None:
    engine = ComplianceGateEngine(policy_path=REPO_ROOT / "policies/cabf_policy.yaml")
    cert = REPO_ROOT / "tests/certificates/expired_cert.pem"
    as_of = "2026-09-18T00:00:00+00:00"
    first, _ = engine.assess(cert_path=cert, evaluated_at=as_of)
    second, _ = engine.assess(cert_path=cert, evaluated_at=as_of)
    assert first.verdict_digest == second.verdict_digest
    assert first.verdict_digest
    assert len(first.verdict_digest) == 64
