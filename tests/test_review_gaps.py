"""0.2.2 review-gap controls: registry, assess/persist, OID/serial/SCT/EKU, signed waivers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import yaml

from certguard.agents.policy_validator import ALL_CONTROL_NAMES, CHECK_METADATA, CONTROLS
from certguard.artifact_signing import generate_ed25519_keypair_b64, sign_bytes
from certguard.engine import ComplianceGateEngine
POLICY_PATH = Path("policies/cabf_policy.yaml")


def _status(report, name: str) -> str:
    return next(check.status for check in report.checks if check.name == name)


def test_controls_registry_covers_every_check() -> None:
    assert tuple(control.name for control in CONTROLS) == ALL_CONTROL_NAMES
    assert set(CHECK_METADATA) == set(ALL_CONTROL_NAMES)
    assert len(ALL_CONTROL_NAMES) == 29


def test_assess_does_not_write_files(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert()
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    report, artifacts = engine.assess(cert_path=cert)

    assert report.compliant is True
    assert "policy_checks" in artifacts
    assert not (tmp_path / "report.json").exists()
    assert not list(tmp_path.glob("**/*.digest"))
    assert not list(tmp_path.glob("**/evidence_manifest.json"))


def test_signature_oid_allowlist_rejects_unknown_oid(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy.setdefault("signature", {})["allowed_oids"] = ["1.2.840.113549.1.1.12"]
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    engine = ComplianceGateEngine(policy_path=policy_path)
    _, report = engine.evaluate(
        make_cert(), tmp_path / "report.json", tmp_path / "evidence"
    )
    assert _status(report, "signature_algorithm_oid") == "fail"


def test_serial_entropy_rejects_short_serial(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    _, report = engine.evaluate(
        make_cert(serial_number=1),
        tmp_path / "report.json",
        tmp_path / "evidence",
    )
    assert _status(report, "serial_entropy") == "fail"


def test_sct_and_eku_are_not_applicable_on_the_default_profile(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    _, report = engine.evaluate(
        make_cert(), tmp_path / "report.json", tmp_path / "evidence"
    )
    assert _status(report, "sct_presence") == "not_applicable"
    assert _status(report, "extended_key_usage") == "not_applicable"
    assert _status(report, "serial_entropy") == "pass"
    assert _status(report, "signature_algorithm_oid") == "pass"


def test_opt_in_sct_and_eku_fail_minted_certificates(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy.setdefault("certificate", {})
    policy["certificate"]["require_sct"] = True
    policy["certificate"]["require_eku"] = True
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    engine = ComplianceGateEngine(policy_path=policy_path)
    _, report = engine.evaluate(
        make_cert(), tmp_path / "report.json", tmp_path / "evidence"
    )
    assert _status(report, "sct_presence") == "fail"
    assert _status(report, "extended_key_usage") == "fail"


def test_opt_in_eku_passes_when_server_auth_is_present(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    policy.setdefault("certificate", {})
    policy["certificate"]["require_eku"] = True
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    engine = ComplianceGateEngine(policy_path=policy_path)
    _, report = engine.evaluate(
        make_cert(include_eku=("1.3.6.1.5.5.7.3.1",)),
        tmp_path / "report.json",
        tmp_path / "evidence",
    )
    assert _status(report, "extended_key_usage") == "pass"


def test_unsigned_waivers_fail_closed_when_required(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    waiver = tmp_path / "waivers.json"
    waiver.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "check": "rsa_key_size",
                        "reason": "pending refresh",
                        "ticket": "SEC-1",
                        "expires_on": "2099-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    compliant, report = engine.evaluate(
        make_cert(key="rsa1024"),
        tmp_path / "report.json",
        tmp_path / "evidence",
        waiver_path=waiver,
        require_signed_waivers=True,
    )
    assert compliant is False
    assert _status(report, "waiver_signature") == "fail"
    assert any(item["name"] == "rsa_key_size" for item in report.failed_controls)


def test_signed_waivers_apply_when_required(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    private_key, public_key = generate_ed25519_keypair_b64()
    unsigned = {
        "waivers": [
            {
                "check": "rsa_key_size",
                "reason": "pending refresh",
                "ticket": "SEC-1",
                "expires_on": "2099-01-01",
            }
        ]
    }
    signature = sign_bytes(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        private_key,
    )
    waiver = tmp_path / "waivers.json"
    waiver.write_text(
        json.dumps({**unsigned, "signature": signature, "public_key": public_key}),
        encoding="utf-8",
    )
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    compliant, report = engine.evaluate(
        make_cert(key="rsa1024"),
        tmp_path / "report.json",
        tmp_path / "evidence",
        waiver_path=waiver,
        require_signed_waivers=True,
    )
    assert compliant is True
    assert report.waived_controls[0]["name"] == "rsa_key_size"
    assert all(check.name != "waiver_signature" for check in report.checks)
