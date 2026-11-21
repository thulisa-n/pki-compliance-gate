"""Deprecation of evidence_signing_key on the public engine API.

The argument still signs the evidence manifest. Callers are warned that it
will be removed. Omitting it does not warn and does not sign.
"""

from __future__ import annotations

import json
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest

from certguard.artifact_signing import generate_ed25519_keypair_b64, verify_signature
from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")
DEPRECATION = "evidence_signing_key is deprecated and will be removed in a future release."
SIGNATURE_NOTE = " manifest_signature is an Ed25519 signature over the unsigned manifest."


def _deprecations(
    caught: list[warnings.WarningMessage],
) -> list[warnings.WarningMessage]:
    return [
        item
        for item in caught
        if issubclass(item.category, DeprecationWarning) and str(item.message) == DEPRECATION
    ]


def _assert_one_deprecation(caught: list[warnings.WarningMessage]) -> None:
    found = _deprecations(caught)
    assert len(found) == 1
    assert found[0].category is DeprecationWarning
    assert Path(found[0].filename).name == "test_evidence_signing_deprecation.py"


def _manifest(evidence_dir: Path) -> dict:
    return json.loads((evidence_dir / "evidence_manifest.json").read_text(encoding="utf-8"))


def _assert_signed(manifest: dict, public_key: str) -> None:
    signed = dict(manifest)
    signature = signed.pop("manifest_signature")
    assert isinstance(signature, str) and signature
    note = signed["integrity_note"]
    assert note.endswith(SIGNATURE_NOTE)
    signed["integrity_note"] = note[: -len(SIGNATURE_NOTE)]
    canonical = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert verify_signature(canonical, signature, public_key)


def test_evaluate_warns_when_evidence_signing_key_is_passed(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    private_key, public_key = generate_ed25519_keypair_b64()
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    evidence_dir = tmp_path / "evidence"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compliant, report = engine.evaluate(
            cert_path=make_cert(),
            report_path=tmp_path / "report.json",
            evidence_dir=evidence_dir,
            evidence_signing_key=private_key,
        )

    _assert_one_deprecation(caught)
    assert isinstance(compliant, bool)
    assert report.certificate
    _assert_signed(_manifest(evidence_dir), public_key)


def test_evaluate_does_not_warn_when_evidence_signing_key_is_absent(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    evidence_dir = tmp_path / "evidence"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine.evaluate(
            cert_path=make_cert(),
            report_path=tmp_path / "report.json",
            evidence_dir=evidence_dir,
        )

    assert _deprecations(caught) == []
    manifest = _manifest(evidence_dir)
    assert "manifest_signature" not in manifest
    assert "manifest_signature" not in manifest["integrity_note"]


def test_evaluate_does_not_warn_when_evidence_signing_key_is_none(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine.evaluate(
            cert_path=make_cert(),
            report_path=tmp_path / "report.json",
            evidence_dir=tmp_path / "evidence",
            evidence_signing_key=None,
        )

    assert _deprecations(caught) == []


def test_empty_evidence_signing_key_warns_without_signing(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    evidence_dir = tmp_path / "evidence"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine.evaluate(
            cert_path=make_cert(),
            report_path=tmp_path / "report.json",
            evidence_dir=evidence_dir,
            evidence_signing_key="",
        )

    _assert_one_deprecation(caught)
    manifest = _manifest(evidence_dir)
    assert "manifest_signature" not in manifest


def test_invalid_evidence_signing_key_still_warns(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(ValueError, match="Invalid base64"):
            engine.evaluate(
                cert_path=make_cert(),
                report_path=tmp_path / "report.json",
                evidence_dir=tmp_path / "evidence",
                evidence_signing_key="not-a-key",
            )

    _assert_one_deprecation(caught)


def test_persist_warns_when_evidence_signing_key_is_passed(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    private_key, public_key = generate_ed25519_keypair_b64()
    cert = make_cert()
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    report, artifacts = engine.assess(cert_path=cert)
    evidence_dir = tmp_path / "evidence"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine.persist(
            report=report,
            artifacts=artifacts,
            report_path=tmp_path / "report.json",
            evidence_dir=evidence_dir,
            cert_path=cert,
            evidence_signing_key=private_key,
        )

    _assert_one_deprecation(caught)
    _assert_signed(_manifest(evidence_dir), public_key)


def test_persist_does_not_warn_when_evidence_signing_key_is_absent(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert()
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    report, artifacts = engine.assess(cert_path=cert)
    evidence_dir = tmp_path / "evidence"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine.persist(
            report=report,
            artifacts=artifacts,
            report_path=tmp_path / "report.json",
            evidence_dir=evidence_dir,
            cert_path=cert,
        )

    assert _deprecations(caught) == []
    assert "manifest_signature" not in _manifest(evidence_dir)


def test_manifest_writer_warns_when_called_directly(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    private_key, public_key = generate_ed25519_keypair_b64()
    cert = make_cert()
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    evidence_dir = tmp_path / "evidence"
    report_path = tmp_path / "report.json"
    engine.evaluate(cert_path=cert, report_path=report_path, evidence_dir=evidence_dir)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine._write_evidence_manifest(
            evidence_dir=evidence_dir,
            report_path=report_path,
            digest_path=tmp_path / "report.json.digest",
            cert_path=cert,
            waiver_path=None,
            evidence_signing_key=private_key,
        )

    _assert_one_deprecation(caught)
    _assert_signed(_manifest(evidence_dir), public_key)


def test_cli_evaluate_does_not_emit_the_signing_deprecation(
    make_cert: Callable[..., Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No CLI flag or policy setting passes evidence_signing_key."""
    from certguard.cli import main

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        code = main(
            [
                "--cert",
                str(make_cert()),
                "--policy",
                str(POLICY_PATH.resolve()),
                "--report",
                str(tmp_path / "report.json"),
                "--evidence-dir",
                str(tmp_path / "evidence"),
                "--output",
                "text",
            ]
        )
    captured = capsys.readouterr()

    assert code == 0
    assert _deprecations(caught) == []
    assert DEPRECATION not in captured.err
    assert "manifest_signature" not in _manifest(tmp_path / "evidence")
