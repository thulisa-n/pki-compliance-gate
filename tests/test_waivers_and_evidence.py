"""Waiver handling and evidence-bundle integrity.

Covers three defects:

* A waived critical finding produced ``failed_controls == []``, therefore
  ``risk_level: LOW`` and exit code 0 -- a waiver silently erased the risk.
* ``_apply_waivers`` mutated the ``CheckResult`` objects owned by the validator
  agent's result, rewriting them after the fact.
* ``evidence_manifest.json`` listed evidence file *paths* with no digests, so
  nothing in the "evidence manifest" could detect that a listed file changed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable


from certguard import __version__
from certguard.cli import _exit_code_from_report
from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _waiver_file(tmp_path: Path, check: str, expires_on: str = "2099-01-01") -> Path:
    path = tmp_path / "waivers.json"
    path.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "check": check,
                        "reason": "Accepted risk pending hardware refresh",
                        "ticket": "SEC-1234",
                        "expires_on": expires_on,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _evaluate(cert: Path, tmp_path: Path, waiver_path: Path | None = None):
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    return engine.evaluate(
        cert_path=cert,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
        waiver_path=waiver_path,
    )


def test_waived_critical_finding_keeps_risk_high(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa1024")
    waiver = _waiver_file(tmp_path, "rsa_key_size")

    compliant, report = _evaluate(cert, tmp_path, waiver)

    assert compliant is True, "waiver suppresses the gate"
    assert report.risk_level == "HIGH", "waiver must not suppress the risk statement"
    assert report.waived_controls[0]["name"] == "rsa_key_size"
    assert report.waived_controls[0]["severity"] == "critical"
    assert report.coverage["waived"] == 1


def test_fail_on_waived_blocks_audit_runs(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa1024")
    waiver = _waiver_file(tmp_path, "rsa_key_size")
    _, report = _evaluate(cert, tmp_path, waiver)

    assert _exit_code_from_report(report) == 0
    assert _exit_code_from_report(report, fail_on_waived=True) == 3


def test_expired_waiver_is_not_applied(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa1024")
    waiver = _waiver_file(tmp_path, "rsa_key_size", expires_on="2020-01-01")

    compliant, report = _evaluate(cert, tmp_path, waiver)

    assert compliant is False
    assert report.coverage["waived"] == 0
    assert report.findings["critical"] == 1


def test_waiver_does_not_mutate_validator_results(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    from certguard.agents.policy_validator import PolicyValidatorAgent
    from certguard.agents.x509_parser import X509ParserAgent
    from certguard.policy import load_policy

    cert = make_cert(key="rsa1024")
    policy = load_policy(POLICY_PATH)
    parser = X509ParserAgent().run({"cert_path": str(cert)})
    validator_result = PolicyValidatorAgent().run(
        {"policy": policy, "parser_data": parser.data}
    )
    original = next(c for c in validator_result.checks if c.name == "rsa_key_size")
    assert original.status == "fail"

    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    waived = engine._apply_waivers(
        list(validator_result.checks), _waiver_file(tmp_path, "rsa_key_size")
    )

    assert waived["summary"]["status"] == "applied"
    assert original.status == "fail", "agent result must not be rewritten"
    assert (
        next(c for c in waived["checks"] if c.name == "rsa_key_size").status == "waived"
    )


def test_evidence_manifest_digests_every_listed_file(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert()
    _evaluate(cert, tmp_path)

    manifest = json.loads(
        (tmp_path / "evidence" / "evidence_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["manifest_version"] == "2.0"
    assert manifest["engine_version"] == __version__
    assert manifest["policy_sha256"]
    assert manifest["certificate_sha256"]
    assert manifest["evidence_files"]

    for entry in manifest["evidence_files"]:
        path = Path(entry["path"])
        assert path.is_file(), f"manifest lists a missing file: {path}"
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        assert entry["sha256"] == expected, f"digest mismatch for {path}"
        assert entry["size_bytes"] == path.stat().st_size


def test_manifest_states_digests_are_not_signatures(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """Overclaiming integrity is the failure mode being guarded against."""
    _evaluate(make_cert(), tmp_path)
    manifest = json.loads(
        (tmp_path / "evidence" / "evidence_manifest.json").read_text(encoding="utf-8")
    )

    assert "not signatures" in manifest["integrity_note"]


def test_manifest_records_the_policy_bytes_that_produced_the_verdict(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _evaluate(make_cert(), tmp_path)
    manifest = json.loads(
        (tmp_path / "evidence" / "evidence_manifest.json").read_text(encoding="utf-8")
    )

    expected = hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()
    assert manifest["policy_sha256"] == expected


def test_decision_log_records_waiver_authorisation(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """Waivers can suppress a gate, so the authorising bytes are recorded."""
    cert = make_cert(key="rsa1024")
    waiver = _waiver_file(tmp_path, "rsa_key_size")
    _evaluate(cert, tmp_path, waiver)

    lines = [
        json.loads(line)
        for line in (tmp_path / "evidence" / "compliance_decisions.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    entry = lines[-1]

    assert entry["waiver_file"] == str(waiver)
    assert entry["waiver_file_sha256"] == hashlib.sha256(
        waiver.read_bytes()
    ).hexdigest()
    assert entry["waived_checks"] == ["rsa_key_size"]
    assert entry["engine_version"] == __version__
    assert entry["policy_sha256"]
    assert "score" not in entry
    assert entry["findings"]["critical"] == 0


def test_decision_log_chain_still_verifies(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    for index in range(3):
        engine.evaluate(
            cert_path=make_cert(),
            report_path=tmp_path / f"report_{index}.json",
            evidence_dir=tmp_path / "evidence",
        )

    ok, message = engine.verify_decision_log_integrity(
        tmp_path / "evidence" / "compliance_decisions.jsonl"
    )
    assert ok, message


def test_waiver_file_is_listed_in_the_manifest(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa1024")
    waiver = _waiver_file(tmp_path, "rsa_key_size")
    _evaluate(cert, tmp_path, waiver)

    manifest = json.loads(
        (tmp_path / "evidence" / "evidence_manifest.json").read_text(encoding="utf-8")
    )
    listed = {entry["path"] for entry in manifest["evidence_files"]}
    assert str(waiver) in listed


def test_digest_no_longer_claims_immutability(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _evaluate(make_cert(), tmp_path)
    digest = json.loads(
        (tmp_path / "report.json.digest").read_text(encoding="utf-8")
    )
    seal = json.loads(
        (tmp_path / "report.json.seal").read_text(encoding="utf-8")
    )

    assert digest == seal
    assert digest["sha256_fingerprint"]
    assert digest["integrity_note"] == "SHA-256 digest, not a signature."
