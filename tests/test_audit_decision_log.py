from __future__ import annotations

import json
from pathlib import Path

from certguard.engine import ComplianceGateEngine


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_compliance_decision_log_written_and_chained(tmp_path: Path) -> None:
    engine = ComplianceGateEngine(policy_path=Path("policies/cabf_policy.yaml"))
    evidence_dir = tmp_path / "audit_evidence"

    engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=tmp_path / "report_1.json",
        evidence_dir=evidence_dir,
    )
    engine.evaluate(
        cert_path=Path("tests/certificates/sha1_cert.pem"),
        report_path=tmp_path / "report_2.json",
        evidence_dir=evidence_dir,
    )

    log_path = evidence_dir / "compliance_decisions.jsonl"
    assert log_path.exists()
    entries = _read_jsonl(log_path)
    assert len(entries) == 2
    assert entries[0]["entry_hash"]
    assert entries[1]["entry_hash"]
    assert entries[0]["previous_entry_hash"] is None
    assert entries[1]["previous_entry_hash"] == entries[0]["entry_hash"]


def test_verify_decision_log_integrity_passes_for_untampered_log(tmp_path: Path) -> None:
    engine = ComplianceGateEngine(policy_path=Path("policies/cabf_policy.yaml"))
    evidence_dir = tmp_path / "audit_evidence"

    engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=tmp_path / "report_1.json",
        evidence_dir=evidence_dir,
    )
    engine.evaluate(
        cert_path=Path("tests/certificates/sha1_cert.pem"),
        report_path=tmp_path / "report_2.json",
        evidence_dir=evidence_dir,
    )

    ok, details = engine.verify_decision_log_integrity(
        evidence_dir / "compliance_decisions.jsonl"
    )
    assert ok is True
    assert "verified" in details.lower()


def test_verify_decision_log_integrity_detects_tampered_middle_entry(
    tmp_path: Path,
) -> None:
    engine = ComplianceGateEngine(policy_path=Path("policies/cabf_policy.yaml"))
    evidence_dir = tmp_path / "audit_evidence"

    engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=tmp_path / "report_1.json",
        evidence_dir=evidence_dir,
    )
    engine.evaluate(
        cert_path=Path("tests/certificates/sha1_cert.pem"),
        report_path=tmp_path / "report_2.json",
        evidence_dir=evidence_dir,
    )
    engine.evaluate(
        cert_path=Path("tests/certificates/no_san_cert.pem"),
        report_path=tmp_path / "report_3.json",
        evidence_dir=evidence_dir,
    )

    log_path = evidence_dir / "compliance_decisions.jsonl"
    entries = _read_jsonl(log_path)
    entries[1]["compliant"] = True
    tampered_lines = [json.dumps(entry, sort_keys=True) for entry in entries]
    log_path.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")

    ok, details = engine.verify_decision_log_integrity(log_path)
    assert ok is False
    assert "entry_hash mismatch" in details
