"""Report schema 2.0: no percentage score, honest coverage, versioned output.

Regression tests for the defect where controls the policy had not enabled were
recorded as ``status: "pass"`` and counted toward a percentage. On the shipped
default profile that produced ``score: 100.0`` while only 6 of 19 controls were
actually evaluated, and a certificate failing a *critical* control still
reported 94.74%.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from certguard import REPORT_SCHEMA_VERSION, __version__
from certguard.engine import ComplianceGateEngine
from certguard.models import CheckResult, ComplianceReport, risk_level_for

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _evaluate(cert_path: Path, tmp_path: Path):
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    compliant, report = engine.evaluate(
        cert_path=cert_path,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
    )
    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    return compliant, report, payload


def test_report_carries_no_percentage_score(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report, payload = _evaluate(make_cert(), tmp_path)

    assert "score" not in payload
    assert not hasattr(report, "score")


def test_disabled_controls_are_not_applicable_not_pass(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report, payload = _evaluate(make_cert(), tmp_path)

    disabled = [
        check
        for check in payload["checks"]
        if "disabled by policy" in check["details"]
        or "not applicable" in check["details"].lower()
    ]
    assert disabled, "default profile is expected to leave some controls off"
    assert all(check["status"] == "not_applicable" for check in disabled)
    # None of them may be counted as a pass.
    assert report.coverage["passed"] == len(
        [c for c in payload["checks"] if c["status"] == "pass"]
    )
    assert report.coverage["not_applicable"] == len(disabled)


def test_coverage_distinguishes_defined_from_evaluated(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report, _ = _evaluate(make_cert(), tmp_path)
    coverage = report.coverage

    assert coverage["controls_defined"] > coverage["controls_evaluated"]
    assert coverage["controls_evaluated"] == (
        coverage["passed"] + coverage["failed"] + coverage["waived"]
    )
    assert coverage["controls_defined"] == (
        coverage["controls_evaluated"] + coverage["not_applicable"]
    )


def test_findings_are_bucketed_by_severity(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report, payload = _evaluate(make_cert(key="rsa1024"), tmp_path)

    assert payload["findings"]["critical"] == 1
    assert payload["findings"]["high"] == 0
    assert report.findings["critical"] == 1


def test_report_records_engine_and_schema_version(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """A finding that cannot name the code that produced it is not reproducible."""
    _, _, payload = _evaluate(make_cert(), tmp_path)

    assert payload["engine_version"] == __version__
    assert payload["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert payload["policy_version"]


def test_compliant_report_has_no_findings(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    compliant, report, _ = _evaluate(make_cert(), tmp_path)

    assert compliant is True
    assert sum(report.findings.values()) == 0
    assert report.risk_level == "LOW"


def test_empty_profile_cannot_look_fully_assessed() -> None:
    """The core dishonesty: nothing evaluated must not read as success."""
    checks = [
        CheckResult(name="a", status="not_applicable", details="off", severity="high"),
        CheckResult(name="b", status="not_applicable", details="off", severity="high"),
    ]
    report = ComplianceReport.new(
        certificate="x.pem",
        compliant=True,
        checks=checks,
        parser_data={},
        lint={"status": "skipped"},
        policy_version="test",
    )

    assert report.coverage["controls_evaluated"] == 0
    assert report.coverage["controls_defined"] == 2
    assert sum(report.findings.values()) == 0


def test_risk_level_accounts_for_lint_failure() -> None:
    """A lint-only failure previously reported LOW while non-compliant."""
    assert risk_level_for([], [], "fail") == "MEDIUM"
    assert risk_level_for([], [], "pass") == "LOW"


def test_risk_level_is_not_suppressed_by_a_waiver() -> None:
    """A waiver suppresses the gate, never the risk statement."""
    waived_critical = [{"name": "rsa_key_size", "severity": "critical"}]

    assert risk_level_for([], waived_critical, "pass") == "HIGH"


def test_check_result_status_replacement_does_not_mutate_original() -> None:
    original = CheckResult(
        name="rsa_key_size", status="fail", details="weak", severity="critical"
    )
    clone = original.replace_status("waived", "weak Waived: ticket X.")

    assert original.status == "fail"
    assert original.details == "weak"
    assert clone.status == "waived"
    assert clone.severity == "critical"
