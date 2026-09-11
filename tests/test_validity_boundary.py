"""Pin the validity-period interpretation.

CA/Browser Forum BR 1.6.1 defines the Validity Period as the period from
notBefore through notAfter. Some implementations read that inclusively and
arrive at a figure one day larger than ``notAfter - notBefore``. CertGuard
measures the whole-day difference, so a certificate issued for exactly N days
reports N and passes a limit of N.

The interpretation is asserted here at max-1, max and max+1 so it cannot drift
silently. On the headline control, an off-by-one is not a rounding detail.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest
import yaml

from certguard.agents.x509_parser import X509ParserAgent
from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")
MAX_VALIDITY_DAYS = 200


def _policy_with_max(tmp_path: Path, max_days: int) -> Path:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["certificate"]["max_validity_days"] = max_days
    path = tmp_path / f"policy_{max_days}.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("validity_days", "expected_status"),
    [
        (MAX_VALIDITY_DAYS - 1, "pass"),
        (MAX_VALIDITY_DAYS, "pass"),
        (MAX_VALIDITY_DAYS + 1, "fail"),
    ],
)
def test_validity_boundary_is_inclusive_of_the_limit(
    make_cert: Callable[..., Path],
    tmp_path: Path,
    validity_days: int,
    expected_status: str,
) -> None:
    cert = make_cert(validity_days=validity_days)
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    _, report = engine.evaluate(
        cert_path=cert,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
    )

    check = next(c for c in report.checks if c.name == "validity_days")
    assert check.status == expected_status
    assert check.actual_value == validity_days
    assert check.policy_value == MAX_VALIDITY_DAYS


@pytest.mark.parametrize("validity_days", [1, 47, 90, 100, 200, 398])
def test_parser_reports_requested_validity_exactly(
    make_cert: Callable[..., Path], validity_days: int
) -> None:
    """No drift between requested span and reported validity_days."""
    cert = make_cert(validity_days=validity_days)
    result = X509ParserAgent().run({"cert_path": str(cert)})

    assert result.data["validity_days"] == validity_days


@pytest.mark.parametrize("max_days", [47, 100, 200])
def test_scheduled_limits_are_enforceable(
    make_cert: Callable[..., Path], tmp_path: Path, max_days: int
) -> None:
    """Each SC-081v3 phase limit must gate exactly at its boundary."""
    policy = _policy_with_max(tmp_path, max_days)
    engine = ComplianceGateEngine(policy_path=policy)

    at_limit = make_cert(validity_days=max_days)
    _, report = engine.evaluate(
        cert_path=at_limit,
        report_path=tmp_path / "at_limit.json",
        evidence_dir=tmp_path / "evidence_at",
    )
    assert next(c for c in report.checks if c.name == "validity_days").status == "pass"

    over_limit = make_cert(validity_days=max_days + 1)
    _, report = engine.evaluate(
        cert_path=over_limit,
        report_path=tmp_path / "over_limit.json",
        evidence_dir=tmp_path / "evidence_over",
    )
    assert next(c for c in report.checks if c.name == "validity_days").status == "fail"
