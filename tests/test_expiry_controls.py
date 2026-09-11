"""Expiry enforcement.

Regression tests for the defect where a certificate that expired in April 2024
evaluated as fully compliant with a perfect score and exit code 0, because
nothing compared notAfter to the evaluation time -- only the length of the
validity window was checked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest
import yaml

from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _evaluate(cert_path: Path, tmp_path: Path, policy: Path = POLICY_PATH):
    engine = ComplianceGateEngine(policy_path=policy)
    compliant, report = engine.evaluate(
        cert_path=cert_path,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
    )
    return compliant, report


def _check(report, name: str):
    return next(c for c in report.checks if c.name == name)


def test_expired_certificate_is_not_compliant(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(starts_in_days=-400, validity_days=90)
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is False
    check = _check(report, "certificate_not_expired")
    assert check.status == "fail"
    assert check.severity == "critical"
    assert report.risk_level == "HIGH"
    assert report.findings["critical"] >= 1


def test_expired_certificate_exits_three(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    from certguard.cli import _exit_code_from_report

    cert = make_cert(starts_in_days=-400, validity_days=90)
    _, report = _evaluate(cert, tmp_path)

    assert _exit_code_from_report(report) == 3


def test_not_yet_valid_certificate_fails(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(starts_in_days=30)
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is False
    check = _check(report, "certificate_not_yet_valid")
    assert check.status == "fail"
    assert "not valid until" in check.details


def test_current_certificate_passes_expiry_controls(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(validity_days=90)
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is True
    assert _check(report, "certificate_not_expired").status == "pass"
    assert _check(report, "certificate_not_yet_valid").status == "pass"


def test_expiry_controls_can_be_disabled_and_report_not_applicable(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """Disabling the control must never present as a pass."""
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["certificate"]["reject_expired"] = False
    policy["certificate"]["reject_not_yet_valid"] = False
    policy_file = tmp_path / "permissive.yaml"
    policy_file.write_text(yaml.safe_dump(policy), encoding="utf-8")

    cert = make_cert(starts_in_days=-400, validity_days=90)
    compliant, report = _evaluate(cert, tmp_path, policy=policy_file)

    assert compliant is True
    expiry = _check(report, "certificate_not_expired")
    assert expiry.status == "not_applicable"
    assert "disabled by policy" in expiry.details
    assert report.coverage["not_applicable"] >= 2


@pytest.mark.parametrize(
    ("remaining_days", "expected_status"),
    [(10, "fail"), (60, "pass")],
)
def test_renewal_window_is_low_severity(
    make_cert: Callable[..., Path],
    tmp_path: Path,
    remaining_days: int,
    expected_status: str,
) -> None:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["certificate"]["warn_if_expires_within_days"] = 30
    policy_file = tmp_path / "warn.yaml"
    policy_file.write_text(yaml.safe_dump(policy), encoding="utf-8")

    cert = make_cert(validity_days=remaining_days)
    _, report = _evaluate(cert, tmp_path, policy=policy_file)

    window = _check(report, "certificate_expiry_window")
    assert window.status == expected_status
    assert window.severity == "low"


def test_renewal_window_only_yields_exit_one(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """A cert inside the renewal window is a low finding, not a hard block."""
    from certguard.cli import _exit_code_from_report

    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["certificate"]["warn_if_expires_within_days"] = 30
    policy_file = tmp_path / "warn.yaml"
    policy_file.write_text(yaml.safe_dump(policy), encoding="utf-8")

    cert = make_cert(validity_days=10)
    _, report = _evaluate(cert, tmp_path, policy=policy_file)

    assert _exit_code_from_report(report) == 1


def test_renewal_window_disabled_by_default(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(validity_days=5)
    _, report = _evaluate(cert, tmp_path)

    assert _check(report, "certificate_expiry_window").status == "not_applicable"


def test_report_records_evaluation_instant(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """Expiry makes the verdict time-dependent, so the instant is recorded."""
    cert = make_cert()
    _, report = _evaluate(cert, tmp_path)

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert payload["parser_data"]["evaluated_at"]
    assert payload["parser_data"]["days_until_expiry"] > 0
