from __future__ import annotations

import json
from pathlib import Path

import pytest

from certguard.artifact_signing import generate_ed25519_keypair_b64
from certguard.release_provenance import (
    generate_release_provenance,
    verify_release_provenance_signature,
)


def test_generate_release_provenance_writes_manifest_and_digest(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.txt"
    artifact.write_text("hello provenance", encoding="utf-8")
    output = tmp_path / "release_provenance.json"

    manifest_path, digest_path, signature_path = generate_release_provenance([artifact], output)

    assert manifest_path.exists()
    assert digest_path.exists()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["artifacts"][0]["path"] == str(artifact)
    assert len(payload["artifacts"][0]["sha256"]) == 64
    assert len(digest_path.read_text(encoding="utf-8").strip()) == 64
    assert signature_path is None


def test_generate_release_provenance_writes_and_verifies_signature(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.txt"
    artifact.write_text("hello signed provenance", encoding="utf-8")
    output = tmp_path / "release_provenance.json"
    private_key, public_key = generate_ed25519_keypair_b64()

    manifest_path, _, signature_path = generate_release_provenance(
        [artifact],
        output,
        signing_private_key_b64=private_key,
        signing_public_key_b64=public_key,
    )
    assert signature_path is not None
    assert manifest_path.exists()
    assert signature_path.exists()
    assert verify_release_provenance_signature(manifest_path, signature_path, public_key) is True
    assert signature_path.with_suffix(".sig.meta.json").exists()


def test_release_provenance_signature_verification_fails_when_tampered(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.txt"
    artifact.write_text("hello signed provenance", encoding="utf-8")
    output = tmp_path / "release_provenance.json"
    private_key, public_key = generate_ed25519_keypair_b64()

    manifest_path, _, signature_path = generate_release_provenance(
        [artifact],
        output,
        signing_private_key_b64=private_key,
        signing_public_key_b64=public_key,
    )
    assert signature_path is not None
    manifest_path.write_text(
        json.dumps({"tampered": True}, indent=2),
        encoding="utf-8",
    )
    assert verify_release_provenance_signature(manifest_path, signature_path, public_key) is False


def test_generate_release_provenance_fails_for_missing_required_artifact(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.json"
    output = tmp_path / "release_provenance.json"
    with pytest.raises(ValueError, match="Missing required provenance artifacts"):
        generate_release_provenance([missing], output)
