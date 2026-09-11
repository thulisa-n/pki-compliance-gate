"""Key algorithm, size and curve enforcement.

Regression tests for the defect where any non-RSA key bypassed key-strength
policy entirely: ``rsa_ok = (not is_rsa) or ...`` meant a 192-bit ECDSA
certificate evaluated as fully compliant with exit code 0. CA/Browser Forum
BR 6.1.5 permits only P-256, P-384 and P-521 for subscriber ECDSA keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest
import yaml

from certguard.engine import ComplianceGateEngine
from certguard.policy import PolicyValidationError, load_policy

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _evaluate(cert_path: Path, tmp_path: Path, policy: Path = POLICY_PATH):
    engine = ComplianceGateEngine(policy_path=policy)
    return engine.evaluate(
        cert_path=cert_path,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
    )


def _check(report, name: str):
    return next(c for c in report.checks if c.name == name)


def _policy_with(tmp_path: Path, **key_overrides) -> Path:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["key"].update(key_overrides)
    path = tmp_path / "key_policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


def test_p192_certificate_is_not_compliant(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="ec192")
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is False
    assert _check(report, "ec_key_size").status == "fail"
    assert _check(report, "ec_curve_allowed").status == "fail"
    assert report.risk_level == "HIGH"
    assert report.findings["critical"] == 2


def test_p192_certificate_exits_three(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    from certguard.cli import _exit_code_from_report

    cert = make_cert(key="ec192")
    _, report = _evaluate(cert, tmp_path)

    assert _exit_code_from_report(report) == 3


@pytest.mark.parametrize("key_kind", ["ec256", "ec384"])
def test_approved_curves_pass(
    make_cert: Callable[..., Path], tmp_path: Path, key_kind: str
) -> None:
    cert = make_cert(key=key_kind)
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is True
    assert _check(report, "ec_key_size").status == "pass"
    assert _check(report, "ec_curve_allowed").status == "pass"
    # RSA-specific control is not applicable to an EC certificate, and must not
    # be recorded as a pass.
    assert _check(report, "rsa_key_size").status == "not_applicable"


def test_rsa_certificate_marks_ec_controls_not_applicable(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa2048")
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is True
    assert _check(report, "rsa_key_size").status == "pass"
    assert _check(report, "ec_key_size").status == "not_applicable"
    assert _check(report, "ec_curve_allowed").status == "not_applicable"


def test_weak_rsa_still_fails(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="rsa1024")
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is False
    check = _check(report, "rsa_key_size")
    assert check.status == "fail"
    assert check.severity == "critical"


def test_ed25519_rejected_by_default_cabf_profile(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """The default profile is a CABF profile, which does not permit Ed25519."""
    cert = make_cert(key="ed25519")
    compliant, report = _evaluate(cert, tmp_path)

    assert compliant is False
    check = _check(report, "key_algorithm_allowed")
    assert check.status == "fail"
    assert check.actual_value == "ed25519"


def test_ed25519_allowed_when_policy_permits_it(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """An internal CA can opt in; the point is that policy decides, not chance."""
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["key"]["allowed_algorithms"] = ["rsa", "ec", "ed25519"]
    policy.setdefault("signature", {}).setdefault("allowed_oids", [])
    if "1.3.101.112" not in policy["signature"]["allowed_oids"]:
        policy["signature"]["allowed_oids"].append("1.3.101.112")
    path = tmp_path / "ed25519_policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    cert = make_cert(key="ed25519")
    compliant, report = _evaluate(cert, tmp_path, policy=path)

    assert compliant is True
    assert _check(report, "key_algorithm_allowed").status == "pass"


def test_curve_allowlist_is_configurable(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    policy = _policy_with(
        tmp_path, allowed_ec_curves=["secp384r1", "secp521r1"], minimum_ec_bits=384
    )
    cert = make_cert(key="ec256")
    compliant, report = _evaluate(cert, tmp_path, policy=policy)

    assert compliant is False
    assert _check(report, "ec_curve_allowed").status == "fail"
    assert _check(report, "ec_key_size").status == "fail"


def test_policy_rejects_unknown_key_algorithm(tmp_path: Path) -> None:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["key"]["allowed_algorithms"] = ["rsa", "quantum-magic"]
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="unsupported algorithms"):
        load_policy(path)


def test_policy_rejects_empty_algorithm_allowlist(tmp_path: Path) -> None:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy["key"]["allowed_algorithms"] = []
    path = tmp_path / "empty.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="at least one algorithm"):
        load_policy(path)


def test_default_profile_enforces_cabf_curves() -> None:
    """Defaults must be correct without the operator configuring anything."""
    policy = load_policy(POLICY_PATH)

    assert policy["key"]["allowed_ec_curves"] == [
        "secp256r1",
        "secp384r1",
        "secp521r1",
    ]
    assert policy["key"]["minimum_ec_bits"] == 256
    assert policy["certificate"]["reject_expired"] is True
